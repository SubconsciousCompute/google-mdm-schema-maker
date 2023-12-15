use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use schemars::{schema_for, JsonSchema};

/// A policy resource represents a group of settings that govern the behavior of a managed device and the apps installed on it.
///
/// # Activities
///
/// This type is used in activities, which are methods you may call on this type or where this type is involved in.
/// The list links the activity name, along with information about where it is used (one of *request* and *response*).
///
/// * [policies get enterprises](EnterprisePolicyGetCall) (response)
/// * [policies patch enterprises](EnterprisePolicyPatchCall) (request|response)
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    // /// Account types that can't be managed by the user.
    // #[serde(rename = "accountTypesWithManagementDisabled")]
    // pub account_types_with_management_disabled: Option<Vec<String>>,
    // /// Whether adding new users and profiles is disabled.
    // #[serde(rename = "addUserDisabled")]
    // pub add_user_disabled: Option<bool>,
    // /// Whether adjusting the master volume is disabled. Also mutes the device.
    // #[serde(rename = "adjustVolumeDisabled")]
    // pub adjust_volume_disabled: Option<bool>,
    // /// Security policies set to secure values by default. To maintain the security posture of a device, we don't recommend overriding any of the default values.
    // #[serde(rename = "advancedSecurityOverrides")]
    // pub advanced_security_overrides: Option<AdvancedSecurityOverrides>,
    // /// Configuration for an always-on VPN connection. Use with vpn_config_disabled to prevent modification of this setting.
    // #[serde(rename = "alwaysOnVpnPackage")]
    // pub always_on_vpn_package: Option<AlwaysOnVpnPackage>,
    // /// The app tracks for Android Device Policy the device can access. The device receives the latest version among all accessible tracks. If no tracks are specified, then the device only uses the production track.
    // #[serde(rename = "androidDevicePolicyTracks")]
    // pub android_device_policy_tracks: Option<Vec<String>>,
    // /// Deprecated. Use autoUpdateMode instead.When autoUpdateMode is set to AUTO_UPDATE_POSTPONED or AUTO_UPDATE_HIGH_PRIORITY, this field has no effect.The app auto update policy, which controls when automatic app updates can be applied.
    // #[serde(rename = "appAutoUpdatePolicy")]
    // pub app_auto_update_policy: Option<String>,
    // /// Policy applied to apps.
    // pub applications: Option<Vec<ApplicationPolicy>>,
    // /// Whether auto date, time, and time zone are enabled on a company-owned device. If this is set, then autoTimeRequired is ignored.
    // #[serde(rename = "autoDateAndTimeZone")]
    // pub auto_date_and_time_zone: Option<String>,
    // /// Whether auto time is required, which prevents the user from manually setting the date and time. If autoDateAndTimeZone is set, this field is ignored.
    // #[serde(rename = "autoTimeRequired")]
    // pub auto_time_required: Option<bool>,
    // /// Whether applications other than the ones configured in applications are blocked from being installed. When set, applications that were installed under a previous policy but no longer appear in the policy are automatically uninstalled.
    // #[serde(rename = "blockApplicationsEnabled")]
    // pub block_applications_enabled: Option<bool>,
    /// Whether configuring bluetooth is disabled.
    #[serde(rename = "bluetoothConfigDisabled")]
    pub bluetooth_config_disabled: Option<bool>,
    // /// Whether bluetooth contact sharing is disabled.
    // #[serde(rename = "bluetoothContactSharingDisabled")]
    // pub bluetooth_contact_sharing_disabled: Option<bool>,
    /// Whether bluetooth is disabled. Prefer this setting over bluetooth_config_disabled because bluetooth_config_disabled can be bypassed by the user.
    #[serde(rename = "bluetoothDisabled")]
    pub bluetooth_disabled: Option<bool>,
    // /// Controls the use of the camera and whether the user has access to the camera access toggle.
    // #[serde(rename = "cameraAccess")]
    // pub camera_access: Option<String>,
    // /// If camera_access is set to any value other than CAMERA_ACCESS_UNSPECIFIED, this has no effect. Otherwise this field controls whether cameras are disabled: If true, all cameras are disabled, otherwise they are available. For fully managed devices this field applies for all apps on the device. For work profiles, this field applies only to apps in the work profile, and the camera access of apps outside the work profile is unaffected.
    // #[serde(rename = "cameraDisabled")]
    // pub camera_disabled: Option<bool>,
    // /// Whether configuring cell broadcast is disabled.
    // #[serde(rename = "cellBroadcastsConfigDisabled")]
    // pub cell_broadcasts_config_disabled: Option<bool>,
    // /// Rules for determining apps' access to private keys. See ChoosePrivateKeyRule for details.
    // #[serde(rename = "choosePrivateKeyRules")]
    // pub choose_private_key_rules: Option<Vec<ChoosePrivateKeyRule>>,
    // /// Rules declaring which mitigating actions to take when a device is not compliant with its policy. When the conditions for multiple rules are satisfied, all of the mitigating actions for the rules are taken. There is a maximum limit of 100 rules. Use policy enforcement rules instead.
    // #[serde(rename = "complianceRules")]
    // pub compliance_rules: Option<Vec<ComplianceRule>>,
    // /// Whether creating windows besides app windows is disabled.
    // #[serde(rename = "createWindowsDisabled")]
    // pub create_windows_disabled: Option<bool>,
    // /// Whether configuring user credentials is disabled.
    // #[serde(rename = "credentialsConfigDisabled")]
    // pub credentials_config_disabled: Option<bool>,
    // /// Cross-profile policies applied on the device.
    // #[serde(rename = "crossProfilePolicies")]
    // pub cross_profile_policies: Option<CrossProfilePolicies>,
    // /// Whether roaming data services are disabled.
    // #[serde(rename = "dataRoamingDisabled")]
    // pub data_roaming_disabled: Option<bool>,
    // /// Whether the user is allowed to enable debugging features.
    // #[serde(rename = "debuggingFeaturesAllowed")]
    // pub debugging_features_allowed: Option<bool>,
    // /// The default permission policy for runtime permission requests.
    // #[serde(rename = "defaultPermissionPolicy")]
    // pub default_permission_policy: Option<String>,
    // /// The device owner information to be shown on the lock screen.
    // #[serde(rename = "deviceOwnerLockScreenInfo")]
    // pub device_owner_lock_screen_info: Option<UserFacingMessage>,
    // /// Whether encryption is enabled
    // #[serde(rename = "encryptionPolicy")]
    // pub encryption_policy: Option<String>,
    // /// Whether app verification is force-enabled.
    // #[serde(rename = "ensureVerifyAppsEnabled")]
    // pub ensure_verify_apps_enabled: Option<bool>,
    // /// Whether factory resetting from settings is disabled.
    // #[serde(rename = "factoryResetDisabled")]
    // pub factory_reset_disabled: Option<bool>,
    // /// Email addresses of device administrators for factory reset protection. When the device is factory reset, it will require one of these admins to log in with the Google account email and password to unlock the device. If no admins are specified, the device won't provide factory reset protection.
    // #[serde(rename = "frpAdminEmails")]
    // pub frp_admin_emails: Option<Vec<String>>,
    // /// Whether the user is allowed to have fun. Controls whether the Easter egg game in Settings is disabled.
    // #[serde(rename = "funDisabled")]
    // pub fun_disabled: Option<bool>,
    // /// Whether user installation of apps is disabled.
    // #[serde(rename = "installAppsDisabled")]
    // pub install_apps_disabled: Option<bool>,
    // /// This field has no effect.
    // #[serde(rename = "installUnknownSourcesAllowed")]
    // pub install_unknown_sources_allowed: Option<bool>,
    // /// If true, this disables the Lock Screen (https://source.android.com/docs/core/display/multi_display/lock-screen) for primary and/or secondary displays.
    // #[serde(rename = "keyguardDisabled")]
    // pub keyguard_disabled: Option<bool>,
    // /// Disabled keyguard customizations, such as widgets.
    // #[serde(rename = "keyguardDisabledFeatures")]
    // pub keyguard_disabled_features: Option<Vec<String>>,
    // /// Whether the kiosk custom launcher is enabled. This replaces the home screen with a launcher that locks down the device to the apps installed via the applications setting. Apps appear on a single page in alphabetical order. Use kioskCustomization to further configure the kiosk device behavior.
    // #[serde(rename = "kioskCustomLauncherEnabled")]
    // pub kiosk_custom_launcher_enabled: Option<bool>,
    // /// Settings controlling the behavior of a device in kiosk mode. To enable kiosk mode, set kioskCustomLauncherEnabled to true or specify an app in the policy with installType KIOSK.
    // #[serde(rename = "kioskCustomization")]
    // pub kiosk_customization: Option<KioskCustomization>,
    /// The degree of location detection enabled.
    #[serde(rename = "locationMode")]
    pub location_mode: Option<String>,
    // /// A message displayed to the user in the device administators settings screen.
    // #[serde(rename = "longSupportMessage")]
    // pub long_support_message: Option<UserFacingMessage>,
    // /// Maximum time in milliseconds for user activity until the device locks. A value of 0 means there is no restriction.
    // #[serde(rename = "maximumTimeToLock")]
    // pub maximum_time_to_lock: Option<i64>,
    // /// Controls the use of the microphone and whether the user has access to the microphone access toggle. This applies only on fully managed devices.
    // #[serde(rename = "microphoneAccess")]
    // pub microphone_access: Option<String>,
    // /// The minimum allowed Android API level.
    // #[serde(rename = "minimumApiLevel")]
    // pub minimum_api_level: Option<i32>,
    // /// Whether configuring mobile networks is disabled.
    // #[serde(rename = "mobileNetworksConfigDisabled")]
    // pub mobile_networks_config_disabled: Option<bool>,
    // /// Whether adding or removing accounts is disabled.
    // #[serde(rename = "modifyAccountsDisabled")]
    // pub modify_accounts_disabled: Option<bool>,
    // /// Whether the user mounting physical external media is disabled.
    // #[serde(rename = "mountPhysicalMediaDisabled")]
    // pub mount_physical_media_disabled: Option<bool>,
    // /// The name of the policy in the form enterprises/{enterpriseId}/policies/{policyId}.
    // pub name: Option<String>,
    // /// Whether the network escape hatch is enabled. If a network connection can't be made at boot time, the escape hatch prompts the user to temporarily connect to a network in order to refresh the device policy. After applying policy, the temporary network will be forgotten and the device will continue booting. This prevents being unable to connect to a network if there is no suitable network in the last policy and the device boots into an app in lock task mode, or the user is otherwise unable to reach device settings.Note: Setting wifiConfigDisabled to true will override this setting under specific circumstances. Please see wifiConfigDisabled for further details.
    // #[serde(rename = "networkEscapeHatchEnabled")]
    // pub network_escape_hatch_enabled: Option<bool>,
    // /// Whether resetting network settings is disabled.
    // #[serde(rename = "networkResetDisabled")]
    // pub network_reset_disabled: Option<bool>,
    // /// This feature is not generally available.
    // #[serde(rename = "oncCertificateProviders")]
    // pub onc_certificate_providers: Option<Vec<OncCertificateProvider>>,
    // /// Network configuration for the device. See configure networks for more information.
    // #[serde(rename = "openNetworkConfiguration")]
    // pub open_network_configuration: Option<HashMap<String, String>>,
    // /// Whether using NFC to beam data from apps is disabled.
    // #[serde(rename = "outgoingBeamDisabled")]
    // pub outgoing_beam_disabled: Option<bool>,
    // /// Whether outgoing calls are disabled.
    // #[serde(rename = "outgoingCallsDisabled")]
    // pub outgoing_calls_disabled: Option<bool>,
    // /// Password requirement policies. Different policies can be set for work profile or fully managed devices by setting the password_scope field in the policy.
    // #[serde(rename = "passwordPolicies")]
    // pub password_policies: Option<Vec<PasswordRequirements>>,
    // /// Password requirements. The field password_requirements.require_password_unlock must not be set. DEPRECATED - Use passwordPolicies.Note:Complexity-based values of PasswordQuality, that is, COMPLEXITY_LOW, COMPLEXITY_MEDIUM, and COMPLEXITY_HIGH, cannot be used here. unified_lock_settings cannot be used here.
    // #[serde(rename = "passwordRequirements")]
    // pub password_requirements: Option<PasswordRequirements>,
    // /// Explicit permission or group grants or denials for all apps. These values override the default_permission_policy.
    // #[serde(rename = "permissionGrants")]
    // pub permission_grants: Option<Vec<PermissionGrant>>,
    // /// Specifies permitted accessibility services. If the field is not set, any accessibility service can be used. If the field is set, only the accessibility services in this list and the system's built-in accessibility service can be used. In particular, if the field is set to empty, only the system's built-in accessibility servicess can be used. This can be set on fully managed devices and on work profiles. When applied to a work profile, this affects both the personal profile and the work profile.
    // #[serde(rename = "permittedAccessibilityServices")]
    // pub permitted_accessibility_services: Option<PackageNameList>,
    // /// If present, only the input methods provided by packages in this list are permitted. If this field is present, but the list is empty, then only system input methods are permitted.
    // #[serde(rename = "permittedInputMethods")]
    // pub permitted_input_methods: Option<PackageNameList>,
    // /// Default intent handler activities.
    // #[serde(rename = "persistentPreferredActivities")]
    // pub persistent_preferred_activities: Option<Vec<PersistentPreferredActivity>>,
    // /// Policies managing personal usage on a company-owned device.
    // #[serde(rename = "personalUsagePolicies")]
    // pub personal_usage_policies: Option<PersonalUsagePolicies>,
    // /// This mode controls which apps are available to the user in the Play Store and the behavior on the device when apps are removed from the policy.
    // #[serde(rename = "playStoreMode")]
    // pub play_store_mode: Option<String>,
    // /// Rules that define the behavior when a particular policy can not be applied on device
    // #[serde(rename = "policyEnforcementRules")]
    // pub policy_enforcement_rules: Option<Vec<PolicyEnforcementRule>>,
    // /// Controls whether preferential network service is enabled on the work profile. For example, an organization may have an agreement with a carrier that all of the work data from its employees' devices will be sent via a network service dedicated for enterprise use. An example of a supported preferential network service is the enterprise slice on 5G networks. This has no effect on fully managed devices.
    // #[serde(rename = "preferentialNetworkService")]
    // pub preferential_network_service: Option<String>,
    // /// Allows showing UI on a device for a user to choose a private key alias if there are no matching rules in ChoosePrivateKeyRules. For devices below Android P, setting this may leave enterprise keys vulnerable.
    // #[serde(rename = "privateKeySelectionEnabled")]
    // pub private_key_selection_enabled: Option<bool>,
    // /// The network-independent global HTTP proxy. Typically proxies should be configured per-network in open_network_configuration. However for unusual configurations like general internal filtering a global HTTP proxy may be useful. If the proxy is not accessible, network access may break. The global proxy is only a recommendation and some apps may ignore it.
    // #[serde(rename = "recommendedGlobalProxy")]
    // pub recommended_global_proxy: Option<ProxyInfo>,
    // /// Whether removing other users is disabled.
    // #[serde(rename = "removeUserDisabled")]
    // pub remove_user_disabled: Option<bool>,
    // /// Whether rebooting the device into safe boot is disabled.
    // #[serde(rename = "safeBootDisabled")]
    // pub safe_boot_disabled: Option<bool>,
    // /// Whether screen capture is disabled.
    // #[serde(rename = "screenCaptureDisabled")]
    // pub screen_capture_disabled: Option<bool>,
    // /// Whether changing the user icon is disabled.
    // #[serde(rename = "setUserIconDisabled")]
    // pub set_user_icon_disabled: Option<bool>,
    // /// Whether changing the wallpaper is disabled.
    // #[serde(rename = "setWallpaperDisabled")]
    // pub set_wallpaper_disabled: Option<bool>,
    // /// Action to take during the setup process. At most one action may be specified.
    // #[serde(rename = "setupActions")]
    // pub setup_actions: Option<Vec<SetupAction>>,
    /// Whether location sharing is disabled. share_location_disabled is supported for both fully managed devices and personally owned work profiles.
    #[serde(rename = "shareLocationDisabled")]
    pub share_location_disabled: Option<bool>,
    // /// A message displayed to the user in the settings screen wherever functionality has been disabled by the admin. If the message is longer than 200 characters it may be truncated.
    // #[serde(rename = "shortSupportMessage")]
    // pub short_support_message: Option<UserFacingMessage>,
    // /// Flag to skip hints on the first use. Enterprise admin can enable the system recommendation for apps to skip their user tutorial and other introductory hints on first start-up.
    // #[serde(rename = "skipFirstUseHintsEnabled")]
    // pub skip_first_use_hints_enabled: Option<bool>,
    // /// Whether sending and receiving SMS messages is disabled.
    // #[serde(rename = "smsDisabled")]
    // pub sms_disabled: Option<bool>,
    // /// Whether the status bar is disabled. This disables notifications, quick settings, and other screen overlays that allow escape from full-screen mode. DEPRECATED. To disable the status bar on a kiosk device, use InstallType KIOSK or kioskCustomLauncherEnabled.
    // #[serde(rename = "statusBarDisabled")]
    // pub status_bar_disabled: Option<bool>,
    // /// Status reporting settings
    // #[serde(rename = "statusReportingSettings")]
    // pub status_reporting_settings: Option<StatusReportingSettings>,
    // /// The battery plugged in modes for which the device stays on. When using this setting, it is recommended to clear maximum_time_to_lock so that the device doesn't lock itself while it stays on.
    // #[serde(rename = "stayOnPluggedModes")]
    // pub stay_on_plugged_modes: Option<Vec<String>>,
    // /// The system update policy, which controls how OS updates are applied. If the update type is WINDOWED, the update window will automatically apply to Play app updates as well.
    // #[serde(rename = "systemUpdate")]
    // pub system_update: Option<SystemUpdate>,
    // /// Whether configuring tethering and portable hotspots is disabled.
    // #[serde(rename = "tetheringConfigDisabled")]
    // pub tethering_config_disabled: Option<bool>,
    // /// Whether user uninstallation of applications is disabled. This prevents apps from being uninstalled, even those removed using applications
    // #[serde(rename = "uninstallAppsDisabled")]
    // pub uninstall_apps_disabled: Option<bool>,
    // /// If microphone_access is set to any value other than MICROPHONE_ACCESS_UNSPECIFIED, this has no effect. Otherwise this field controls whether microphones are disabled: If true, all microphones are disabled, otherwise they are available. This is available only on fully managed devices.
    // #[serde(rename = "unmuteMicrophoneDisabled")]
    // pub unmute_microphone_disabled: Option<bool>,
    // /// Configuration of device activity logging.
    // #[serde(rename = "usageLog")]
    // pub usage_log: Option<UsageLog>,
    // /// Whether transferring files over USB is disabled. This is supported only on company-owned devices.
    // #[serde(rename = "usbFileTransferDisabled")]
    // pub usb_file_transfer_disabled: Option<bool>,
    // /// Whether USB storage is enabled. Deprecated.
    // #[serde(rename = "usbMassStorageEnabled")]
    // pub usb_mass_storage_enabled: Option<bool>,
    // /// The version of the policy. This is a read-only field. The version is incremented each time the policy is updated.
    // pub version: Option<i64>,
    // /// Whether configuring VPN is disabled.
    // #[serde(rename = "vpnConfigDisabled")]
    // pub vpn_config_disabled: Option<bool>,
    // /// Whether configuring Wi-Fi access points is disabled. Note: If a network connection can't be made at boot time and configuring Wi-Fi is disabled then network escape hatch will be shown in order to refresh the device policy (see networkEscapeHatchEnabled).
    // #[serde(rename = "wifiConfigDisabled")]
    // pub wifi_config_disabled: Option<bool>,
    // /// DEPRECATED - Use wifi_config_disabled.
    // #[serde(rename = "wifiConfigsLockdownEnabled")]
    // pub wifi_configs_lockdown_enabled: Option<bool>,
}

/// Security policies set to secure values by default. To maintain the security posture of a device, we don't recommend overriding any of the default values.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct AdvancedSecurityOverrides {
    /// Controls Common Criteria Mode—security standards defined in the Common Criteria for Information Technology Security Evaluation (https://www.commoncriteriaportal.org/) (CC). Enabling Common Criteria Mode increases certain security components on a device, including AES-GCM encryption of Bluetooth Long Term Keys, and Wi-Fi configuration stores.Warning: Common Criteria Mode enforces a strict security model typically only required for IT products used in national security systems and other highly sensitive organizations. Standard device use may be affected. Only enabled if required.
    #[serde(rename = "commonCriteriaMode")]
    pub common_criteria_mode: Option<String>,
    /// Controls access to developer settings: developer options and safe boot. Replaces safeBootDisabled (deprecated) and debuggingFeaturesAllowed (deprecated).
    #[serde(rename = "developerSettings")]
    pub developer_settings: Option<String>,
    /// Whether Google Play Protect verification (https://support.google.com/accounts/answer/2812853) is enforced. Replaces ensureVerifyAppsEnabled (deprecated).
    #[serde(rename = "googlePlayProtectVerifyApps")]
    pub google_play_protect_verify_apps: Option<String>,
    /// Personal apps that can read work profile notifications using a NotificationListenerService (https://developer.android.com/reference/android/service/notification/NotificationListenerService). By default, no personal apps (aside from system apps) can read work notifications. Each value in the list must be a package name.
    #[serde(rename = "personalAppsThatCanReadWorkNotifications")]
    pub personal_apps_that_can_read_work_notifications: Option<Vec<String>>,
    /// The policy for untrusted apps (apps from unknown sources) enforced on the device. Replaces install_unknown_sources_allowed (deprecated).
    #[serde(rename = "untrustedAppsPolicy")]
    pub untrusted_apps_policy: Option<String>,
}

/// Configuration for an always-on VPN connection.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct AlwaysOnVpnPackage {
    /// Disallows networking when the VPN is not connected.
    #[serde(rename = "lockdownEnabled")]
    pub lockdown_enabled: Option<bool>,
    /// The package name of the VPN app.
    #[serde(rename = "packageName")]
    pub package_name: Option<String>,
}

/// Policy for an individual app.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationPolicy {
    /// List of the app’s track IDs that a device belonging to the enterprise can access. If the list contains multiple track IDs, devices receive the latest version among all accessible tracks. If the list contains no track IDs, devices only have access to the app’s production track. More details about each track are available in AppTrackInfo.
    #[serde(rename = "accessibleTrackIds")]
    pub accessible_track_ids: Option<Vec<String>>,
    /// Specifies whether the app is allowed networking when the VPN is not connected and alwaysOnVpnPackage.lockdownEnabled is enabled. If set to VPN_LOCKDOWN_ENFORCED, the app is not allowed networking, and if set to VPN_LOCKDOWN_EXEMPTION, the app is allowed networking. Only supported on devices running Android 10 and above. If this is not supported by the device, the device will contain a NonComplianceDetail with non_compliance_reason set to API_LEVEL and a fieldPath. If this is not applicable to the app, the device will contain a NonComplianceDetail with non_compliance_reason set to UNSUPPORTED and a fieldPath. The fieldPath is set to applications[i].alwaysOnVpnLockdownExemption, where i is the index of the package in the applications policy.
    #[serde(rename = "alwaysOnVpnLockdownExemption")]
    pub always_on_vpn_lockdown_exemption: Option<String>,
    /// Controls the auto-update mode for the app.
    #[serde(rename = "autoUpdateMode")]
    pub auto_update_mode: Option<String>,
    /// Controls whether the app can communicate with itself across a device’s work and personal profiles, subject to user consent.
    #[serde(rename = "connectedWorkAndPersonalApp")]
    pub connected_work_and_personal_app: Option<String>,
    /// The default policy for all permissions requested by the app. If specified, this overrides the policy-level default_permission_policy which applies to all apps. It does not override the permission_grants which applies to all apps.
    #[serde(rename = "defaultPermissionPolicy")]
    pub default_permission_policy: Option<String>,
    /// The scopes delegated to the app from Android Device Policy.
    #[serde(rename = "delegatedScopes")]
    pub delegated_scopes: Option<Vec<String>>,
    /// Whether the app is disabled. When disabled, the app data is still preserved.
    pub disabled: Option<bool>,
    /// Configuration to enable this app as an extension app, with the capability of interacting with Android Device Policy offline.This field can be set for at most one app.
    #[serde(rename = "extensionConfig")]
    pub extension_config: Option<ExtensionConfig>,
    /// The type of installation to perform.
    #[serde(rename = "installType")]
    pub install_type: Option<String>,
    /// Whether the app is allowed to lock itself in full-screen mode. DEPRECATED. Use InstallType KIOSK or kioskCustomLauncherEnabled to configure a dedicated device.
    #[serde(rename = "lockTaskAllowed")]
    pub lock_task_allowed: Option<bool>,
    /// Managed configuration applied to the app. The format for the configuration is dictated by the ManagedProperty values supported by the app. Each field name in the managed configuration must match the key field of the ManagedProperty. The field value must be compatible with the type of the ManagedProperty: *type* *JSON value* BOOL true or false STRING string INTEGER number CHOICE string MULTISELECT array of strings HIDDEN string BUNDLE_ARRAY array of objects
    #[serde(rename = "managedConfiguration")]
    pub managed_configuration: Option<HashMap<String, String>>,
    /// The managed configurations template for the app, saved from the managed configurations iframe. This field is ignored if managed_configuration is set.
    #[serde(rename = "managedConfigurationTemplate")]
    pub managed_configuration_template: Option<ManagedConfigurationTemplate>,
    /// The minimum version of the app that runs on the device. If set, the device attempts to update the app to at least this version code. If the app is not up-to-date, the device will contain a NonComplianceDetail with non_compliance_reason set to APP_NOT_UPDATED. The app must already be published to Google Play with a version code greater than or equal to this value. At most 20 apps may specify a minimum version code per policy.
    #[serde(rename = "minimumVersionCode")]
    pub minimum_version_code: Option<i32>,
    /// The package name of the app. For example, com.google.android.youtube for the YouTube app.
    #[serde(rename = "packageName")]
    pub package_name: Option<String>,
    /// Explicit permission grants or denials for the app. These values override the default_permission_policy and permission_grants which apply to all apps.
    #[serde(rename = "permissionGrants")]
    pub permission_grants: Option<Vec<PermissionGrant>>,
    /// Specifies whether the app installed in the work profile is allowed to add widgets to the home screen.
    #[serde(rename = "workProfileWidgets")]
    pub work_profile_widgets: Option<String>,
}

/// Controls apps' access to private keys. The rule determines which private key, if any, Android Device Policy grants to the specified app. Access is granted either when the app calls KeyChain.choosePrivateKeyAlias (https://developer.android.com/reference/android/security/KeyChain#choosePrivateKeyAlias%28android.app.Activity,%20android.security.KeyChainAliasCallback,%20java.lang.String[],%20java.security.Principal[],%20java.lang.String,%20int,%20java.lang.String%29) (or any overloads) to request a private key alias for a given URL, or for rules that are not URL-specific (that is, if urlPattern is not set, or set to the empty string or .*) on Android 11 and above, directly so that the app can call KeyChain.getPrivateKey (https://developer.android.com/reference/android/security/KeyChain#getPrivateKey%28android.content.Context,%20java.lang.String%29), without first having to call KeyChain.choosePrivateKeyAlias.When an app calls KeyChain.choosePrivateKeyAlias if more than one choosePrivateKeyRules matches, the last matching rule defines which key alias to return.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct ChoosePrivateKeyRule {
    /// The package names to which this rule applies. The hash of the signing certificate for each app is verified against the hash provided by Play. If no package names are specified, then the alias is provided to all apps that call KeyChain.choosePrivateKeyAlias (https://developer.android.com/reference/android/security/KeyChain#choosePrivateKeyAlias%28android.app.Activity,%20android.security.KeyChainAliasCallback,%20java.lang.String[],%20java.security.Principal[],%20java.lang.String,%20int,%20java.lang.String%29) or any overloads (but not without calling KeyChain.choosePrivateKeyAlias, even on Android 11 and above). Any app with the same Android UID as a package specified here will have access when they call KeyChain.choosePrivateKeyAlias.
    #[serde(rename = "packageNames")]
    pub package_names: Option<Vec<String>>,
    /// The alias of the private key to be used.
    #[serde(rename = "privateKeyAlias")]
    pub private_key_alias: Option<String>,
    /// The URL pattern to match against the URL of the request. If not set or empty, it matches all URLs. This uses the regular expression syntax of java.util.regex.Pattern.
    #[serde(rename = "urlPattern")]
    pub url_pattern: Option<String>,
}

/// A rule declaring which mitigating actions to take when a device is not compliant with its policy. For every rule, there is always an implicit mitigating action to set policy_compliant to false for the Device resource, and display a message on the device indicating that the device is not compliant with its policy. Other mitigating actions may optionally be taken as well, depending on the field values in the rule.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceRule {
    /// A condition which is satisfied if the Android Framework API level on the device doesn't meet a minimum requirement.
    #[serde(rename = "apiLevelCondition")]
    pub api_level_condition: Option<ApiLevelCondition>,
    /// If set to true, the rule includes a mitigating action to disable apps so that the device is effectively disabled, but app data is preserved. If the device is running an app in locked task mode, the app will be closed and a UI showing the reason for non-compliance will be displayed.
    #[serde(rename = "disableApps")]
    pub disable_apps: Option<bool>,
    /// A condition which is satisfied if there exists any matching NonComplianceDetail for the device.
    #[serde(rename = "nonComplianceDetailCondition")]
    pub non_compliance_detail_condition: Option<NonComplianceDetailCondition>,
    /// If set, the rule includes a mitigating action to disable apps specified in the list, but app data is preserved.
    #[serde(rename = "packageNamesToDisable")]
    pub package_names_to_disable: Option<Vec<String>>,
}

/// Cross-profile policies applied on the device.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct CrossProfilePolicies {
    /// Whether text copied from one profile (personal or work) can be pasted in the other profile.
    #[serde(rename = "crossProfileCopyPaste")]
    pub cross_profile_copy_paste: Option<String>,
    /// Whether data from one profile (personal or work) can be shared with apps in the other profile. Specifically controls simple data sharing via intents. Management of other cross-profile communication channels, such as contact search, copy/paste, or connected work & personal apps, are configured separately.
    #[serde(rename = "crossProfileDataSharing")]
    pub cross_profile_data_sharing: Option<String>,
    /// Whether contacts stored in the work profile can be shown in personal profile contact searches and incoming calls.
    #[serde(rename = "showWorkContactsInPersonalProfile")]
    pub show_work_contacts_in_personal_profile: Option<String>,
    /// Specifies the default behaviour for work profile widgets. If the policy does not specify work_profile_widgets for a specific application, it will behave according to the value specified here.
    #[serde(rename = "workProfileWidgetsDefault")]
    pub work_profile_widgets_default: Option<String>,
}

/// Provides a user-facing message with locale info. The maximum message length is 4096 characters.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct UserFacingMessage {
    /// The default message displayed if no localized message is specified or the user's locale doesn't match with any of the localized messages. A default message must be provided if any localized messages are provided.
    #[serde(rename = "defaultMessage")]
    pub default_message: Option<String>,
    /// A map containing pairs, where locale is a well-formed BCP 47 language (https://www.w3.org/International/articles/language-tags/) code, such as en-US, es-ES, or fr.
    #[serde(rename = "localizedMessages")]
    pub localized_messages: Option<HashMap<String, String>>,
}

/// Settings controlling the behavior of a device in kiosk mode. To enable kiosk mode, set kioskCustomLauncherEnabled to true or specify an app in the policy with installType KIOSK.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct KioskCustomization {
    /// Specifies whether the Settings app is allowed in kiosk mode.
    #[serde(rename = "deviceSettings")]
    pub device_settings: Option<String>,
    /// Sets the behavior of a device in kiosk mode when a user presses and holds (long-presses) the Power button.
    #[serde(rename = "powerButtonActions")]
    pub power_button_actions: Option<String>,
    /// Specifies whether system info and notifications are disabled in kiosk mode.
    #[serde(rename = "statusBar")]
    pub status_bar: Option<String>,
    /// Specifies whether system error dialogs for crashed or unresponsive apps are blocked in kiosk mode. When blocked, the system will force-stop the app as if the user chooses the "close app" option on the UI.
    #[serde(rename = "systemErrorWarnings")]
    pub system_error_warnings: Option<String>,
    /// Specifies which navigation features are enabled (e.g. Home, Overview buttons) in kiosk mode.
    #[serde(rename = "systemNavigation")]
    pub system_navigation: Option<String>,
}

/// This feature is not generally available.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct OncCertificateProvider {
    /// This feature is not generally available.
    #[serde(rename = "certificateReferences")]
    pub certificate_references: Option<Vec<String>>,
    /// This feature is not generally available.
    #[serde(rename = "contentProviderEndpoint")]
    pub content_provider_endpoint: Option<ContentProviderEndpoint>,
}

/// Requirements for the password used to unlock a device.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct PasswordRequirements {
    /// Number of incorrect device-unlock passwords that can be entered before a device is wiped. A value of 0 means there is no restriction.
    #[serde(rename = "maximumFailedPasswordsForWipe")]
    pub maximum_failed_passwords_for_wipe: Option<i32>,
    /// Password expiration timeout.
    #[serde(rename = "passwordExpirationTimeout")]
    pub password_expiration_timeout: Option<String>,
    /// The length of the password history. After setting this field, the user won't be able to enter a new password that is the same as any password in the history. A value of 0 means there is no restriction.
    #[serde(rename = "passwordHistoryLength")]
    pub password_history_length: Option<i32>,
    /// The minimum allowed password length. A value of 0 means there is no restriction. Only enforced when password_quality is NUMERIC, NUMERIC_COMPLEX, ALPHABETIC, ALPHANUMERIC, or COMPLEX.
    #[serde(rename = "passwordMinimumLength")]
    pub password_minimum_length: Option<i32>,
    /// Minimum number of letters required in the password. Only enforced when password_quality is COMPLEX.
    #[serde(rename = "passwordMinimumLetters")]
    pub password_minimum_letters: Option<i32>,
    /// Minimum number of lower case letters required in the password. Only enforced when password_quality is COMPLEX.
    #[serde(rename = "passwordMinimumLowerCase")]
    pub password_minimum_lower_case: Option<i32>,
    /// Minimum number of non-letter characters (numerical digits or symbols) required in the password. Only enforced when password_quality is COMPLEX.
    #[serde(rename = "passwordMinimumNonLetter")]
    pub password_minimum_non_letter: Option<i32>,
    /// Minimum number of numerical digits required in the password. Only enforced when password_quality is COMPLEX.
    #[serde(rename = "passwordMinimumNumeric")]
    pub password_minimum_numeric: Option<i32>,
    /// Minimum number of symbols required in the password. Only enforced when password_quality is COMPLEX.
    #[serde(rename = "passwordMinimumSymbols")]
    pub password_minimum_symbols: Option<i32>,
    /// Minimum number of upper case letters required in the password. Only enforced when password_quality is COMPLEX.
    #[serde(rename = "passwordMinimumUpperCase")]
    pub password_minimum_upper_case: Option<i32>,
    /// The required password quality.
    #[serde(rename = "passwordQuality")]
    pub password_quality: Option<String>,
    /// The scope that the password requirement applies to.
    #[serde(rename = "passwordScope")]
    pub password_scope: Option<String>,
    /// The length of time after a device or work profile is unlocked using a strong form of authentication (password, PIN, pattern) that it can be unlocked using any other authentication method (e.g. fingerprint, trust agents, face). After the specified time period elapses, only strong forms of authentication can be used to unlock the device or work profile.
    #[serde(rename = "requirePasswordUnlock")]
    pub require_password_unlock: Option<String>,
    /// Controls whether a unified lock is allowed for the device and the work profile, on devices running Android 9 and above with a work profile. This can be set only if password_scope is set to SCOPE_PROFILE, the policy will be rejected otherwise. If user has not set a separate work lock and this field is set to REQUIRE_SEPARATE_WORK_LOCK, a NonComplianceDetail is reported with nonComplianceReason set to USER_ACTION.
    #[serde(rename = "unifiedLockSettings")]
    pub unified_lock_settings: Option<String>,
}

/// A list of package names.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct PackageNameList {
    /// A list of package names.
    #[serde(rename = "packageNames")]
    pub package_names: Option<Vec<String>>,
}

/// Configuration for an Android permission and its grant state.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct PermissionGrant {
    /// The Android permission or group, e.g. android.permission.READ_CALENDAR or android.permission_group.CALENDAR.
    pub permission: Option<String>,
    /// The policy for granting the permission.
    pub policy: Option<String>,
}

/// A compliance rule condition which is satisfied if the Android Framework API level on the device doesn't meet a minimum requirement. There can only be one rule with this type of condition per policy.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct ApiLevelCondition {
    /// The minimum desired Android Framework API level. If the device doesn't meet the minimum requirement, this condition is satisfied. Must be greater than zero.
    #[serde(rename = "minApiLevel")]
    pub min_api_level: Option<i32>,
}

/// This feature is not generally available.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct ContentProviderEndpoint {
    /// This feature is not generally available.
    #[serde(rename = "packageName")]
    pub package_name: Option<String>,
    /// Required. This feature is not generally available.
    #[serde(rename = "signingCertsSha256")]
    pub signing_certs_sha256: Option<Vec<String>>,
    /// This feature is not generally available.
    pub uri: Option<String>,
}

/// Configuration to enable an app as an extension app, with the capability of interacting with Android Device Policy offline. For Android versions 13 and above, extension apps are exempt from battery restrictions so will not be placed into the restricted App Standby Bucket (https://developer.android.com/topic/performance/appstandby#restricted-bucket). Extensions apps are also protected against users clearing their data or force-closing the application, although admins can continue to use the clear app data command (https://developer.android.com/management/reference/rest/v1/enterprises.devices/issueCommand#CommandType) on extension apps if needed for Android 13 and above.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct ExtensionConfig {
    /// Fully qualified class name of the receiver service class for Android Device Policy to notify the extension app of any local command status updates.
    #[serde(rename = "notificationReceiver")]
    pub notification_receiver: Option<String>,
    /// Hex-encoded SHA-256 hash of the signing certificate of the extension app. Only hexadecimal string representations of 64 characters are valid.If not specified, the signature for the corresponding package name is obtained from the Play Store instead.If this list is empty, the signature of the extension app on the device must match the signature obtained from the Play Store for the app to be able to communicate with Android Device Policy.If this list is not empty, the signature of the extension app on the device must match one of the entries in this list for the app to be able to communicate with Android Device Policy.In production use cases, it is recommended to leave this empty.
    #[serde(rename = "signingKeyFingerprintsSha256")]
    pub signing_key_fingerprints_sha256: Option<Vec<String>>,
}

/// The managed configurations template for the app, saved from the managed configurations iframe.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct ManagedConfigurationTemplate {
    /// Optional, a map containing configuration variables defined for the configuration.
    #[serde(rename = "configurationVariables")]
    pub configuration_variables: Option<HashMap<String, String>>,
    /// The ID of the managed configurations template.
    #[serde(rename = "templateId")]
    pub template_id: Option<String>,
}

/// A compliance rule condition which is satisfied if there exists any matching NonComplianceDetail for the device. A NonComplianceDetail matches a NonComplianceDetailCondition if all the fields which are set within the NonComplianceDetailCondition match the corresponding NonComplianceDetail fields.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct NonComplianceDetailCondition {
    /// The reason the device is not in compliance with the setting. If not set, then this condition matches any reason.
    #[serde(rename = "nonComplianceReason")]
    pub non_compliance_reason: Option<String>,
    /// The package name of the app that's out of compliance. If not set, then this condition matches any package name.
    #[serde(rename = "packageName")]
    pub package_name: Option<String>,
    /// The name of the policy setting. This is the JSON field name of a top-level Policy field. If not set, then this condition matches any setting name.
    #[serde(rename = "settingName")]
    pub setting_name: Option<String>,
}

/// A default activity for handling intents that match a particular intent filter. Note: To set up a kiosk, use InstallType to KIOSK rather than use persistent preferred activities.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct PersistentPreferredActivity {
    /// The intent actions to match in the filter. If any actions are included in the filter, then an intent's action must be one of those values for it to match. If no actions are included, the intent action is ignored.
    pub actions: Option<Vec<String>>,
    /// The intent categories to match in the filter. An intent includes the categories that it requires, all of which must be included in the filter in order to match. In other words, adding a category to the filter has no impact on matching unless that category is specified in the intent.
    pub categories: Option<Vec<String>>,
    /// The activity that should be the default intent handler. This should be an Android component name, e.g. com.android.enterprise.app/.MainActivity. Alternatively, the value may be the package name of an app, which causes Android Device Policy to choose an appropriate activity from the app to handle the intent.
    #[serde(rename = "receiverActivity")]
    pub receiver_activity: Option<String>,
}

/// Policies controlling personal usage on a company-owned device with a work profile.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct PersonalUsagePolicies {
    /// Account types that can't be managed by the user.
    #[serde(rename = "accountTypesWithManagementDisabled")]
    pub account_types_with_management_disabled: Option<Vec<String>>,
    /// If true, the camera is disabled on the personal profile.
    #[serde(rename = "cameraDisabled")]
    pub camera_disabled: Option<bool>,
    /// Controls how long the work profile can stay off. The duration must be at least 3 days.
    #[serde(rename = "maxDaysWithWorkOff")]
    pub max_days_with_work_off: Option<i32>,
    /// Policy applied to applications in the personal profile.
    #[serde(rename = "personalApplications")]
    pub personal_applications: Option<Vec<PersonalApplicationPolicy>>,
    /// Used together with personalApplications to control how apps in the personal profile are allowed or blocked.
    #[serde(rename = "personalPlayStoreMode")]
    pub personal_play_store_mode: Option<String>,
    /// If true, screen capture is disabled for all users.
    #[serde(rename = "screenCaptureDisabled")]
    pub screen_capture_disabled: Option<bool>,
}

/// A rule that defines the actions to take if a device or work profile is not compliant with the policy specified in settingName.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct PolicyEnforcementRule {
    /// An action to block access to apps and data on a company owned device or in a work profile. This action also triggers a user-facing notification with information (where possible) on how to correct the compliance issue. Note: wipeAction must also be specified.
    #[serde(rename = "blockAction")]
    pub block_action: Option<BlockAction>,
    /// The top-level policy to enforce. For example, applications or passwordPolicies.
    #[serde(rename = "settingName")]
    pub setting_name: Option<String>,
    /// An action to reset a company owned device or delete a work profile. Note: blockAction must also be specified.
    #[serde(rename = "wipeAction")]
    pub wipe_action: Option<WipeAction>,
}

/// An action to block access to apps and data on a fully managed device or in a work profile. This action also triggers a device or work profile to displays a user-facing notification with information (where possible) on how to correct the compliance issue. Note: wipeAction must also be specified.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct BlockAction {
    /// Number of days the policy is non-compliant before the device or work profile is blocked. To block access immediately, set to 0. blockAfterDays must be less than wipeAfterDays.
    #[serde(rename = "blockAfterDays")]
    pub block_after_days: Option<i32>,
    /// Specifies the scope of this BlockAction. Only applicable to devices that are company-owned.
    #[serde(rename = "blockScope")]
    pub block_scope: Option<String>,
}

/// Policies for apps in the personal profile of a company-owned device with a work profile.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct PersonalApplicationPolicy {
    /// The type of installation to perform.
    #[serde(rename = "installType")]
    pub install_type: Option<String>,
    /// The package name of the application.
    #[serde(rename = "packageName")]
    pub package_name: Option<String>,
}

/// Configuration info for an HTTP proxy. For a direct proxy, set the host, port, and excluded_hosts fields. For a PAC script proxy, set the pac_uri field.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct ProxyInfo {
    /// For a direct proxy, the hosts for which the proxy is bypassed. The host names may contain wildcards such as *.example.com.
    #[serde(rename = "excludedHosts")]
    pub excluded_hosts: Option<Vec<String>>,
    /// The host of the direct proxy.
    pub host: Option<String>,
    /// The URI of the PAC script used to configure the proxy.
    #[serde(rename = "pacUri")]
    pub pac_uri: Option<String>,
    /// The port of the direct proxy.
    pub port: Option<i32>,
}

/// An action executed during setup.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct SetupAction {
    /// Description of this action.
    pub description: Option<UserFacingMessage>,
    /// An action to launch an app. The app will be launched with an intent containing an extra with key com.google.android.apps.work.clouddpc.EXTRA_LAUNCHED_AS_SETUP_ACTION set to the boolean value true to indicate that this is a setup action flow. If SetupAction references an app, the corresponding installType in the application policy must be set as REQUIRED_FOR_SETUP or said setup will fail.
    #[serde(rename = "launchApp")]
    pub launch_app: Option<LaunchAppAction>,
    /// Title of this action.
    pub title: Option<UserFacingMessage>,
}

/// Settings controlling the behavior of status reports.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct StatusReportingSettings {
    /// Application reporting settings. Only applicable if application_reports_enabled is true.
    #[serde(rename = "applicationReportingSettings")]
    pub application_reporting_settings: Option<ApplicationReportingSettings>,
    /// Whether app reports are enabled.
    #[serde(rename = "applicationReportsEnabled")]
    pub application_reports_enabled: Option<bool>,
    /// Whether Common Criteria Mode reporting is enabled.
    #[serde(rename = "commonCriteriaModeEnabled")]
    pub common_criteria_mode_enabled: Option<bool>,
    /// Whether device settings reporting is enabled.
    #[serde(rename = "deviceSettingsEnabled")]
    pub device_settings_enabled: Option<bool>,
    /// Whether displays reporting is enabled. Report data is not available for personally owned devices with work profiles.
    #[serde(rename = "displayInfoEnabled")]
    pub display_info_enabled: Option<bool>,
    /// Whether hardware status reporting is enabled. Report data is not available for personally owned devices with work profiles.
    #[serde(rename = "hardwareStatusEnabled")]
    pub hardware_status_enabled: Option<bool>,
    /// Whether memory event reporting is enabled.
    #[serde(rename = "memoryInfoEnabled")]
    pub memory_info_enabled: Option<bool>,
    /// Whether network info reporting is enabled.
    #[serde(rename = "networkInfoEnabled")]
    pub network_info_enabled: Option<bool>,
    /// Whether power management event reporting is enabled. Report data is not available for personally owned devices with work profiles.
    #[serde(rename = "powerManagementEventsEnabled")]
    pub power_management_events_enabled: Option<bool>,
    /// Whether software info reporting is enabled.
    #[serde(rename = "softwareInfoEnabled")]
    pub software_info_enabled: Option<bool>,
    /// Whether system properties reporting is enabled.
    #[serde(rename = "systemPropertiesEnabled")]
    pub system_properties_enabled: Option<bool>,
}

/// Configuration for managing system updates
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct SystemUpdate {
    /// If the type is WINDOWED, the end of the maintenance window, measured as the number of minutes after midnight in device's local time. This value must be between 0 and 1439, inclusive. If this value is less than start_minutes, then the maintenance window spans midnight. If the maintenance window specified is smaller than 30 minutes, the actual window is extended to 30 minutes beyond the start time.
    #[serde(rename = "endMinutes")]
    pub end_minutes: Option<i32>,
    /// An annually repeating time period in which over-the-air (OTA) system updates are postponed to freeze the OS version running on a device. To prevent freezing the device indefinitely, each freeze period must be separated by at least 60 days.
    #[serde(rename = "freezePeriods")]
    pub freeze_periods: Option<Vec<FreezePeriod>>,
    /// If the type is WINDOWED, the start of the maintenance window, measured as the number of minutes after midnight in the device's local time. This value must be between 0 and 1439, inclusive.
    #[serde(rename = "startMinutes")]
    pub start_minutes: Option<i32>,
    /// The type of system update to configure.
    #[serde(rename = "type")]
    pub type_: Option<String>,
}

/// Settings controlling the behavior of application reports.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationReportingSettings {
    /// Whether removed apps are included in application reports.
    #[serde(rename = "includeRemovedApps")]
    pub include_removed_apps: Option<bool>,
}

/// A system freeze period. When a device’s clock is within the freeze period, all incoming system updates (including security patches) are blocked and won’t be installed. When a device is outside the freeze period, normal update behavior applies. Leap years are ignored in freeze period calculations, in particular: * If Feb. 29th is set as the start or end date of a freeze period, the freeze period will start or end on Feb. 28th instead. * When a device’s system clock reads Feb. 29th, it’s treated as Feb. 28th. * When calculating the number of days in a freeze period or the time between two freeze periods, Feb. 29th is ignored and not counted as a day.Note: For Freeze Periods to take effect, SystemUpdateType cannot be specified as SYSTEM_UPDATE_TYPE_UNSPECIFIED, because freeze periods require a defined policy to be specified.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct FreezePeriod {
    /// The end date (inclusive) of the freeze period. Must be no later than 90 days from the start date. If the end date is earlier than the start date, the freeze period is considered wrapping year-end. Note: year must not be set. For example, {"month": 1,"date": 30}.
    #[serde(rename = "endDate")]
    pub end_date: Option<Date>,
    /// The start date (inclusive) of the freeze period. Note: year must not be set. For example, {"month": 1,"date": 30}.
    #[serde(rename = "startDate")]
    pub start_date: Option<Date>,
}

/// An action to launch an app.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct LaunchAppAction {
    /// Package name of app to be launched
    #[serde(rename = "packageName")]
    pub package_name: Option<String>,
}

/// Controls types of device activity logs collected from the device and reported via Pub/Sub notification (https://developers.google.com/android/management/notifications).
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct UsageLog {
    /// Specifies which log types are enabled. Note that users will receive on-device messaging when usage logging is enabled.
    #[serde(rename = "enabledLogTypes")]
    pub enabled_log_types: Option<Vec<String>>,
    /// Specifies which of the enabled log types can be uploaded over mobile data. By default logs are queued for upload when the device connects to WiFi.
    #[serde(rename = "uploadOnCellularAllowed")]
    pub upload_on_cellular_allowed: Option<Vec<String>>,
}

/// An action to reset a company owned device or delete a work profile. Note: blockAction must also be specified.
///
/// This type is not used in any activity, and only used as *part* of another schema.
///
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct WipeAction {
    /// Whether the factory-reset protection data is preserved on the device. This setting doesn’t apply to work profiles.
    #[serde(rename = "preserveFrp")]
    pub preserve_frp: Option<bool>,
    /// Number of days the policy is non-compliant before the device or work profile is wiped. wipeAfterDays must be greater than blockAfterDays.
    #[serde(rename = "wipeAfterDays")]
    pub wipe_after_days: Option<i32>,
}

/// Represents a whole or partial calendar date, such as a birthday. The time of day and time zone are either specified elsewhere or are insignificant. The date is relative to the Gregorian Calendar. This can represent one of the following: A full date, with non-zero year, month, and day values. A month and day, with a zero year (for example, an anniversary). A year on its own, with a zero month and a zero day. A year and month, with a zero day (for example, a credit card expiration date).Related types: google.type.TimeOfDay google.type.DateTime google.protobuf.Timestamp
///
/// This type is not used in any activity, and only used as *part* of another schema.
#[derive(JsonSchema, Default, Clone, Debug, Serialize, Deserialize)]
pub struct Date {
    /// Day of a month. Must be from 1 to 31 and valid for the year and month, or 0 to specify a year by itself or a year and month where the day isn't significant.
    pub day: Option<i32>,
    /// Month of a year. Must be from 1 to 12, or 0 to specify a year without a month and day.
    pub month: Option<i32>,
    /// Year of the date. Must be from 1 to 9999, or 0 to specify a date without a year.
    pub year: Option<i32>,
}

fn main() {
    let schema = schema_for!(Policy);
    fs::write("schema", serde_json::to_string_pretty(&schema).unwrap()).expect("Unable to write file");
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
}
