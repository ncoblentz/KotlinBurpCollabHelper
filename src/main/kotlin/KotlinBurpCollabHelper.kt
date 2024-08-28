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
import com.nickcoblentz.montoya.CollabHelper
import com.nickcoblentz.montoya.CollabHelperInteractionFilter
import com.nickcoblentz.montoya.settings.*
import de.milchreis.uibooster.model.Form
import de.milchreis.uibooster.model.FormBuilder
import java.awt.Component
import java.util.UUID
import java.util.function.BiConsumer
import java.util.regex.Pattern

// Montoya API Documentation: https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html
// Montoya Extension Examples: https://github.com/PortSwigger/burp-extensions-montoya-api-examples

class KotlinBurpCollabHelper : BurpExtension {
    private lateinit var api: MontoyaApi

    // Uncomment this section if you wish to use persistent settings and automatic UI Generation from: https://github.com/ncoblentz/BurpMontoyaLibrary
    // Add one or more persistent settings here

    private lateinit var collabFlagItemRegex: StringExtensionSetting
    private lateinit var collabHelper : CollabHelper

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

        collabFlagItemRegex = StringExtensionSetting(
            // pass the montoya API to the setting
            api,
            // Give the setting a name which will show up in the Swing UI Form
            "RegEx to Match and Create an Audit Issue",
            // Key for where to save this setting in Burp's persistence store
            "$PLUGIN_NAME.regex",
            // Default value within the Swing UI Form
            "nothingtomatchhere!!donotmatch!",
            // Whether to save it for this specific "PROJECT" or as a global Burp "PREFERENCE"
            ExtensionSettingSaveLocation.PROJECT
        )

        // Create a list of all the settings defined above
        // Don't forget to add more settings here if you define them above

        collabHelper = CollabHelper(api)

        val collabFilter = CollabHelperInteractionFilter()
            .withInteractionType(InteractionType.HTTP)
            .withHttpRequestPattern(collabFlagItemRegex.currentValue)
            .withInteractionHandler(::handleInteraction)

        collabHelper.interactionObservers.add(collabFilter::handleInteraction)


        val extensionSetting = mutableListOf(collabFlagItemRegex)
        extensionSetting.addAll(collabHelper.extensionSettings)


        val gen = GenericExtensionSettingsFormGenerator(extensionSetting, PLUGIN_NAME)
        gen.addSaveCallback { formElement, form ->
            collabFilter.httpRequestPattern=collabFlagItemRegex.currentValue
        }
        val settingsFormBuilder: FormBuilder = gen.getSettingsFormBuilder()
        val settingsForm: Form = settingsFormBuilder.run()

        // Tell Burp we want a right mouse click context menu for accessing the settings
        api.userInterface().registerContextMenuItemsProvider(ExtensionSettingsContextMenuProvider(api, settingsForm))

        // When we unload this extension, include a callback that closes any Swing UI forms instead of just leaving them still open
        api.extension().registerUnloadingHandler(ExtensionSettingsUnloadHandler(settingsForm))


        // See logging comment above
        api.logging().logToOutput("...Finished loading the extension")

    }

    /*private fun handleInteraction(interaction : Interaction) {
        api.logging().logToOutput("Made it in here")
        if(collabFlagItemRegex.currentValue.isNotBlank() &&
            interaction.type() == InteractionType.HTTP &&
            interaction.httpDetails().isPresent) {

            val request = interaction.httpDetails().get().requestResponse().request()
            val requestString = request.toString()
            val pattern = Pattern.compile(collabFlagItemRegex.currentValue)


            //api.logging().logToOutput(requestString)

            //api.logging().logToOutput("${Regex(collabFlagItemRegex.currentValue)}")
            val matcher = pattern.matcher(requestString)
            if(matcher.find()) {
                api.logging().logToOutput("Found something!")
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
    }*/

    private fun handleInteraction(interaction : Interaction) {
        api.logging().logToOutput("Found something!")
        val requestResponse = interaction.httpDetails().get().requestResponse()
        val request = requestResponse.request()
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