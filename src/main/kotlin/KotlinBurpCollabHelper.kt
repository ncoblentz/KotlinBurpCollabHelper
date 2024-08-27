import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.*
import burp.api.montoya.extension.ExtensionUnloadingHandler
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent
import com.nickcoblentz.montoya.settings.*
import de.milchreis.uibooster.model.Form
import de.milchreis.uibooster.model.FormBuilder
import java.awt.Component
import java.util.UUID
import java.util.regex.Pattern

// Montoya API Documentation: https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html
// Montoya Extension Examples: https://github.com/PortSwigger/burp-extensions-montoya-api-examples

class KotlinBurpCollabHelper : BurpExtension, ContextMenuItemsProvider {
    private lateinit var api: MontoyaApi
    private lateinit var collaboratorClient: CollaboratorClient
    private var shouldPollForInteactions = true
    private var pollCollabThread : Thread? = null

    // Uncomment this section if you wish to use persistent settings and automatic UI Generation from: https://github.com/ncoblentz/BurpMontoyaLibrary
    // Add one or more persistent settings here
    private lateinit var collabPayloadsSetting : StringExtensionSetting
    private lateinit var collabSecretSetting: StringExtensionSetting
    private lateinit var collabFlagItemRegex: StringExtensionSetting

    companion object {
        private const val PLUGIN_NAME: String = "Collab Helper"
        private const val AUDIT_ISSUE_NAME = "Regex Matched Collaborator Interaction"
        private const val AUDIT_ISSUE_DETAIL = "Regex: "
        private const val AUDIT_ISSUE_REMEDIATION = ""
        private const val AUDIT_ISSUE_BACKGROUND = ""
        private const val AUDIT_ISSUE_REMEDIATION_BACKGROUND = ""
    }


    override fun initialize(api: MontoyaApi?) {

        // In Kotlin, you have to explicitly define variables as nullable with a ? as in MontoyaApi? above
        // This is necessary because the Java Library allows null to be passed into this function
        // requireNotNull is a built-in Kotlin function to check for null and throw an Illegal Argument exception if it is null
        // after checking for null, the Kotlin compiler knows that any reference to api below will not = null and you no longer have to check it
        requireNotNull(api) { "api : MontoyaApi is not allowed to be null" }

        // Assign the MontoyaApi instance (not nullable) to a class instance variable to be accessible from other functions in this class
        this.api = api

        // This will print to Burp Suite's Extension output and can be used to debug whether the extension loaded properly
        api.logging().logToOutput("Started loading the extension...")

        // Name our extension when it is displayed inside of Burp Suite
        api.extension().setName(PLUGIN_NAME)


        collabPayloadsSetting = StringExtensionSetting(
            // pass the montoya API to the setting
            api,
            // Give the setting a name which will show up in the Swing UI Form
            "Collaborator Server",
            // Key for where to save this setting in Burp's persistence store
            "$PLUGIN_NAME.payload",
            // Default value within the Swing UI Form
            "",
            // Whether to save it for this specific "PROJECT" or as a global Burp "PREFERENCE"
            ExtensionSettingSaveLocation.PROJECT
            )

        collabSecretSetting = StringExtensionSetting(
            // pass the montoya API to the setting
            api,
            // Give the setting a name which will show up in the Swing UI Form
            "Collaborator Secret",
            // Key for where to save this setting in Burp's persistence store
            "$PLUGIN_NAME.secret",
            // Default value within the Swing UI Form
            "",
            // Whether to save it for this specific "PROJECT" or as a global Burp "PREFERENCE"
            ExtensionSettingSaveLocation.PROJECT
        )

        collabFlagItemRegex = StringExtensionSetting(
            // pass the montoya API to the setting
            api,
            // Give the setting a name which will show up in the Swing UI Form
            "RegEx to Match and Create an Audit Issue",
            // Key for where to save this setting in Burp's persistence store
            "$PLUGIN_NAME.regex",
            // Default value within the Swing UI Form
            "",
            // Whether to save it for this specific "PROJECT" or as a global Burp "PREFERENCE"
            ExtensionSettingSaveLocation.PROJECT
        )

        // Create a list of all the settings defined above
        // Don't forget to add more settings here if you define them above
        val extensionSetting = listOf(collabSecretSetting,collabPayloadsSetting,collabFlagItemRegex)

         if(collabSecretSetting.currentValue.isBlank()) {
            collaboratorClient = api.collaborator().createClient()
            collabSecretSetting.currentValue=collaboratorClient.secretKey.toString()
            collabSecretSetting.save()

        }
        else {
             collaboratorClient = api.collaborator().restoreClient(SecretKey.secretKey(collabSecretSetting.currentValue))
        }

        if(collabPayloadsSetting.currentValue.isBlank()) {
            collabPayloadsSetting.currentValue = collaboratorClient.generatePayload().toString()
            collabPayloadsSetting.save()
        }



        pollCollabThread = Thread.ofVirtual().name("Poll Collaborator").start {

            val threadId = UUID.randomUUID().toString()
            api.logging().logToOutput("Beginning: $threadId")
            while (shouldPollForInteactions) {
                api.logging().logToOutput("In loop: $threadId")
                val allInteractions = collaboratorClient.allInteractions
                api.logging().logToOutput("${allInteractions.size} Total interactions")

                val pattern = Pattern.compile(collabFlagItemRegex.currentValue)

                for(interaction in allInteractions) {
                    api.logging().logToOutput("${interaction.timeStamp()} ${interaction.type()} ${interaction.clientIp()} ${interaction.clientPort()}")
                    if(collabFlagItemRegex.currentValue.isNotBlank() &&
                        interaction.type() == InteractionType.HTTP &&
                        interaction.httpDetails().isPresent) {

                        val request = interaction.httpDetails().get().requestResponse().request()
                        val requestString = request.toString()

                        //api.logging().logToOutput(requestString)

                        //api.logging().logToOutput("${Regex(collabFlagItemRegex.currentValue)}")
                        val matcher = pattern.matcher(requestString)
                        if(matcher.find()) {
                            //api.logging().logToOutput("Found something!")
                            val auditIssue = AuditIssue.auditIssue(
                                AUDIT_ISSUE_NAME,
                                AUDIT_ISSUE_DETAIL,
                                AUDIT_ISSUE_REMEDIATION,
                                request.url(),
                                AuditIssueSeverity.INFORMATION,
                                AuditIssueConfidence.FIRM,
                                AUDIT_ISSUE_BACKGROUND,
                                AUDIT_ISSUE_REMEDIATION_BACKGROUND,
                                AuditIssueSeverity.INFORMATION,
                                interaction.httpDetails().get().requestResponse()
                            )
                            api.siteMap().add(auditIssue)
                        }

                    }
                }
                Thread.sleep(5000) // Wait for 5 seconds before fetching again
            }
            api.logging().logToOutput("Exited: $threadId")
        }

        val gen = GenericExtensionSettingsFormGenerator(extensionSetting, PLUGIN_NAME)
        val settingsFormBuilder: FormBuilder = gen.getSettingsFormBuilder()
        val settingsForm: Form = settingsFormBuilder.run()

        // Tell Burp we want a right mouse click context menu for accessing the settings
        api.userInterface().registerContextMenuItemsProvider(ExtensionSettingsContextMenuProvider(api, settingsForm))

        // When we unload this extension, include a callback that closes any Swing UI forms instead of just leaving them still open
        api.extension().registerUnloadingHandler(ExtensionSettingsUnloadHandler(settingsForm))
        api.extension().registerUnloadingHandler(ExtensionUnloadingHandler {
            api.logging().logToOutput("Shutting down virtual thread")
            shouldPollForInteactions=false
            pollCollabThread?.join()
        })

        // Code for setting up your extension starts here...





        // Code for setting up your extension ends here

        // See logging comment above
        api.logging().logToOutput("...Finished loading the extension")

    }

    override fun provideMenuItems(event: ContextMenuEvent?): MutableList<Component> {
        return super.provideMenuItems(event)
    }

    override fun provideMenuItems(event: WebSocketContextMenuEvent?): MutableList<Component> {
        return super.provideMenuItems(event)
    }

    override fun provideMenuItems(event: AuditIssueContextMenuEvent?): MutableList<Component> {
        return super.provideMenuItems(event)
    }
}