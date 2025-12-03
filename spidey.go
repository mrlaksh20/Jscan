package main

import (
    "bufio"
    "context"
    "flag"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "sync"
    "sync/atomic"
    "time"
)

const (
    maxConcurrency = 10
    requestTimeout = 15 * time.Second
  // Scan up to 2MB per response (optional safety)
)

// ----- GLOBAL REGEX CACHE -----
var regexes = map[string]*regexp.Regexp{
	"google_api": regexp.MustCompile(`(?i)AIza[0-9A-Za-z-_]{35}`),
	"GenericPass": regexp.MustCompile(`(?i)((password|sshpass|senha|pwd|LDAP_REP_PASS|api-key|api_key|creds|credential))`),	
	"firebase": regexp.MustCompile(`(?i)AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`),
	"google_captcha": regexp.MustCompile(`(?i)6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$`),
	"google_oauth": regexp.MustCompile(`(?i)ya29\.[0-9A-Za-z\-_]+`),
	"amazon_aws_access_key_id": regexp.MustCompile(`(?i)A[SK]IA[0-9A-Z]{16}`),
	"amazon_mws_auth_token": regexp.MustCompile(`(?i)amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	"amazon_aws_url": regexp.MustCompile(`(?i)s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com`),
	"facebook_access_token": regexp.MustCompile(`(?i)EAACEdEose0cBA[0-9A-Za-z]+`),
	"authorization_basic": regexp.MustCompile(`(?i)basic [a-zA-Z0-9=:_\+\/-]{5,100}`),
	"authorization_bearer": regexp.MustCompile(`(?i)bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}`),
	"authorization_api": regexp.MustCompile(`(?i)api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}`),
	"mailgun_api_key": regexp.MustCompile(`(?i)key-[0-9a-zA-Z]{32}`),
	"twilio_api_key": regexp.MustCompile(`(?i)SK[0-9a-fA-F]{32}`),
	"twilio_account_sid": regexp.MustCompile(`(?i)AC[a-zA-Z0-9_\-]{32}`),
	"twilio_app_sid": regexp.MustCompile(`(?i)AP[a-zA-Z0-9_\-]{32}`),
	"paypal_braintree_access_token": regexp.MustCompile(`(?i)access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),
	"square_oauth_secret": regexp.MustCompile(`(?i)sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`),
	"square_access_token": regexp.MustCompile(`(?i)sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}`),
	"stripe_standard_api": regexp.MustCompile(`(?i)sk_live_[0-9a-zA-Z]{24}`),
	"stripe_restricted_api": regexp.MustCompile(`(?i)rk_live_[0-9a-zA-Z]{24}`),
	"github_access_token": regexp.MustCompile(`(?i)[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*`),
	"rsa_private_key": regexp.MustCompile(`(?i)-----BEGIN RSA PRIVATE KEY-----`),
	"ssh_dsa_private_key": regexp.MustCompile(`(?i)-----BEGIN DSA PRIVATE KEY-----`),
	"ssh_ec_private_key": regexp.MustCompile(`(?i)-----BEGIN EC PRIVATE KEY-----`),
	"pgp_private_block": regexp.MustCompile(`(?i)-----BEGIN PGP PRIVATE KEY BLOCK-----`),
	"json_web_token": regexp.MustCompile(`(?i)ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`),
	"slack_token": regexp.MustCompile(`(?i)\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"`),
	"ssh_priv_key": regexp.MustCompile(`(?i)([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)`),
	"Bearer_Auth": regexp.MustCompile(`(?i)((?i)bearer\s+([a-zA-Z0-9_\-\.=]+))`),
	"AWS_Client": regexp.MustCompile(`(?i)((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|ANPA|ANVA|ASIA)([A-Z0-9]{16}))`),
	"AWS_Secret": regexp.MustCompile(`(?i)(\s+|)[\"']?((?:aws)?_?(?:secret)?_?(?:access)?_?key)[\"']?\s*(:|=>|=)\s*[\"']?(?P<secret>[A-Za-z0-9\/\+=]{40})[\"']?`),
	"AWS_MWS": regexp.MustCompile(`(?i)(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`),
	"Amazon_AWS_S3_Bucket": regexp.MustCompile(`(?i)//s3-[a-z0-9-]+\.amazonaws\.com/[a-z0-9._-]+`),
	"Discord_Attachments": regexp.MustCompile(`(?i)((media|cdn)\.)?(discordapp\.net/attachments|discordapp\.com/attachments)/.+[a-z]`),
	"Discord_BOT_Token": regexp.MustCompile(`(?i)((?:N|M|O)[a-zA-Z0-9]{23}\.[a-zA-Z0-9-_]{6}\.[a-zA-Z0-9-_]{27})$`),
	"Bitcoin_Wallet_Address": regexp.MustCompile(`(?i)^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$`),
	"GitHub": regexp.MustCompile(`(?i)[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"]{1}[0-9a-zA-Z]{35,40}['|\"]{1}`),
	"Google_API_Key": regexp.MustCompile(`(?i)AIza[0-9A-Za-z\-_]{35}`),
	"Heroku_API_Key": regexp.MustCompile(`(?i)[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`),
	"IP_Address": regexp.MustCompile(`(?i)^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$`),
	"URL": regexp.MustCompile(`(?i)http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!\*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+`),
	"Monero_Wallet_Address": regexp.MustCompile(`(?i)4[0-9AB][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{93}`),
	"Mac_Address": regexp.MustCompile(`(?i)(([0-9A-Fa-f]{2}[:]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{2}[-]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{4}[\.]){2}[0-9A-Fa-f]{4})$`),
	"Mailto": regexp.MustCompile(`(?i)mailto:([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+)`),
	"Onion": regexp.MustCompile(`(?i)([a-z2-7]{16}|[a-z2-7]{56}).onion`),
	"Telegram_BOT_Token": regexp.MustCompile(`(?i)\d{9}:[0-9A-Za-z_-]{35}`),
	"GitHub Generic": regexp.MustCompile(`(?i)([gG][iI][tT][hH][uU][bB].*['\"][0-9a-zA-Z]{35,40}['\"])`),
	"GitHub Personal Token": regexp.MustCompile(`(?i)(ghp_[a-zA-Z0-9]{36})`),
	"GitHub Actions Token": regexp.MustCompile(`(?i)(ghs_[a-zA-Z0-9]{36})`),
	"GitHub Fine-grained Token": regexp.MustCompile(`(?i)(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})`),
	"GitLab Personal Access Token": regexp.MustCompile(`(?i)(glpat-[0-9a-zA-Z\-]{20})`),
	"Generic API Key": regexp.MustCompile(`(?i)[\"']?([a-zA-Z0-9_-]*api[_-]?key)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9\-]{16,})[\"']`),
	"Generic Secret": regexp.MustCompile("(?i)[\"']?([a-zA-Z0-9_-]*secret)[\"']?\\s*[:=]\\s*[\"']([a-zA-Z0-9!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?]{6,})[\"']"),
	"JDBC Connection String with Credentials": regexp.MustCompile(`(?i)((mongodb(\+srv)?:\/\/[^:]+(?::[^@]+)?@[^\/]+\/[^?]+(\?[^=&]+=[^&]+(&[^=&]+=[^&]+)*)?|mysql:\/\/jdbc:mysql:\/\/[^:]+:[^@]+@[^:]+:\d+\/[^\s]+|jdbc:(mysql:\/\/[^:]+(?::\d+)?\/[^?]+(\?[^=&]+=[^&]+(&[^=&]+=[^&]+)*)?|postgresql:\/\/[^:]+(?::\d+)?\/[^?]+(\?[^=&]+=[^&]+(&[^=&]+=[^&]+)*)?|oracle:thin:@[^:]+(?::\d+)?:[^:]+)))`),
	"jdbc": regexp.MustCompile(`(?i)((mongodb(\+srv)?:\/\/[^:]+(?::[^@]+)?@[^\/]+\/[^?]+(\?[^=&]+=[^&]+(&[^=&]+=[^&]+)*)?|jdbc:(mysql:\/\/[^:]+(?:\d+)?\/[^?]+(\?[^=&]+=[^&]+(&[^=&]+=[^&]+)*)?|postgresql:\/\/[^:]+(?:\d+)?\/[^?]+(\?[^=&]+=[^&]+(&[^=&]+=[^&]+)*)?|oracle:thin:@[^:]+(?:\d+)?:[^:]+)))`),
	"Google Cloud Platform API Key": regexp.MustCompile(`(?i)(AIza[0-9A-Za-z\-_]{35})`),
	"Google Cloud Platform OAuth": regexp.MustCompile(`(?i)([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)`),
	"Google Drive API Key": regexp.MustCompile(`(?i)(AIza[0-9A-Za-z\-_]{35})`),
	"Google Drive OAuth": regexp.MustCompile(`(?i)([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)`),
	"Google (GCP) Service-account": regexp.MustCompile(`(?i)(\"type\":\s*\"service_account\")`),
	"HEROKU_API": regexp.MustCompile(`(?i)([hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})`),
	"MAILGUN_API": regexp.MustCompile(`(?i)(key-[0-9a-zA-Z]{32})`),
	"MD5 Hash": regexp.MustCompile(`(?i)\b([a-f0-9]{32})\b`),
	"SLACK_WEBHOOK": regexp.MustCompile(`(?i)(https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24})`),
	"SSH (ed25519) Private Key": regexp.MustCompile(`(?i)(-----BEGIN OPENSSH PRIVATE KEY-----)`),
	"Twilio API Key": regexp.MustCompile(`(?i)(SK[0-9a-fA-F]{32})`),
	"Twitter Access Token": regexp.MustCompile(`(?i)([tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40})`),
	"DigitalOcean Token": regexp.MustCompile(`(?i)(do_[a-f0-9]{64})`),
	"Stripe API Key": regexp.MustCompile(`(?i)(sk_live_[0-9a-zA-Z]{24})`),
	"Square Access Token": regexp.MustCompile(`(?i)(sq0atp-[0-9A-Za-z\-_]{22})`),
	"SendGrid API Key": regexp.MustCompile(`(?i)(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})`),
	"Dropbox API Token": regexp.MustCompile(`(?i)(sl\.[A-Za-z0-9\-_]{60})`),
	"SSH Private Key": regexp.MustCompile(`(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----)`),
	"Private Key": regexp.MustCompile(`(?i)(-----BEGIN PRIVATE KEY-----)`),
	"Jenkins_API_Token": regexp.MustCompile(`(?i)(jenkins_api_token[\s]*[:=][\s]*['\"](\w{32})['\"])`),
	"Jenkins_Crumb": regexp.MustCompile(`(?i)(jenkins-crumb[\s]*[:=][\s]*['\"](\w{32})['\"])`),
	"MS_Teams_Webhook": regexp.MustCompile(`(?i)(https://[a-zA-Z0-9]+\.webhook\.office\.com/webhookb2/[a-zA-Z0-9-]+@[a-zA-Z0-9-]+/IncomingWebhook/[a-zA-Z0-9]+/[a-zA-Z0-9-]+)`),
	"Azure_Sensitive_Info": regexp.MustCompile(`(?i)((azure|connection string|app(?:lication)?\s*(?:id|key|secret)|client\s*(?:id|secret)|access\s*(?:key|token))\s*[:=]\s*['\"]([a-zA-Z0-9+/=_\-]{16,})['\"](\s|$))`),
	"DBs": regexp.MustCompile(`(?i)((mongodb|mysql|orcl|postgresql|sqlserver).{0,100})`),
	"Mysql Connection String": regexp.MustCompile(`(?i)(?:mysql://)?jdbc:mysql://(?P<username>[^:]+):(?P<password>[^@]+)@(?P<host>[^:/\s]+)(?::(?P<port>\d+))?/(?P<dbname>[^?\s]+)(?:\?.*?)?`),
	"Google Cloud Platform Service Account": regexp.MustCompile(`(?i)[0-9]+-[0-9a-z]{32}@[0-9a-z]{32}(?:\.apps\.googleusercontent\.com|\.iam\.gserviceaccount\.com|-gcp-sa\.iam\.gserviceaccount\.com|\.gserviceaccount\.com)?`),
	"AWS AppSync GraphQL Key": regexp.MustCompile(`(?i)da2-[a-z0-9]{26}`),
	"Facebook Access Token": regexp.MustCompile(`(?i)EAACEdEose0cBA[0-9A-Za-z]+`),
	"Facebook Client ID": regexp.MustCompile(`(?i)[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}[0-9]{13,17}`),
	"Facebook Client Secret": regexp.MustCompile(`(?i)[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}[0-9a-zA-Z]{32}`),
	"Facebook OAuth Access Token": regexp.MustCompile(`(?i)[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}['|\"][0-9]{13,17}['|\"]`),
	"Facebook OAuth Secret": regexp.MustCompile(`(?i)[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}['|\"][0-9a-zA-Z]{32}['|\"]`),
	"Facebook OAuth Token": regexp.MustCompile(`(?i)[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}['|\"][0-9a-f]{32}['|\"]`),
	"LinkedIn Client ID": regexp.MustCompile(`(?i)[lL][iI][nN][kK][eE][dD][iI][nN].{0,20}[0-9a-z]{12}`),
	"LinkedIn Client Secret": regexp.MustCompile(`(?i)[lL][iI][nN][kK][eE][dD][iI][nN].{0,20}[0-9a-zA-Z]{16}`),
	"LinkedIn OAuth Access Token": regexp.MustCompile(`(?i)[lL][iI][nN][kK][eE][dD][iI][nN].{0,20}['|\"][0-9a-zA-Z]{16}['|\"]`),
	"Google (GCP) OAuth Access Token": regexp.MustCompile(`(?i)[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
	"Heroku API Key": regexp.MustCompile(`(?i)[hH][eE][rR][oO][kK][uU].{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`),
	"JSON Web Token": regexp.MustCompile(`(?i)eyJhbGciOiJ`),
	"JSON Web Token 2": regexp.MustCompile(`(?i)ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*`),
	"MailChimp API Key": regexp.MustCompile(`(?i)[0-9a-f]{32}-us[0-9]{1,2}`),
	"Mailgun API Key": regexp.MustCompile(`(?i)key-[0-9a-zA-Z]{32}`),
	"Password in URL": regexp.MustCompile(`(?i)[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}[\"'\s]`),
	"PayPal Braintree Access Token": regexp.MustCompile(`(?i)access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),
	"PayPal Braintree Sandbox Access Token": regexp.MustCompile(`(?i)access_token\$sandbox\$[0-9a-z]{16}\$[0-9a-f]{32}`),
	"PayPal Client ID": regexp.MustCompile(`(?i)AdAt[0-9a-z]{32}`),
	"PayPal Secret": regexp.MustCompile(`(?i)Esk[0-9a-z]{32}`),
	"Paystack Secret Key": regexp.MustCompile(`(?i)sk_test_[0-9a-zA-Z]{30}`),
	"Picatic API Key": regexp.MustCompile(`(?i)sk_live_[0-9a-z]{32}`),
	"Slack Webhook": regexp.MustCompile(`(?i)https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`),
	"Stripe Restricted API Key": regexp.MustCompile(`(?i)rk_live_[0-9a-zA-Z]{24}`),
	"Stripe Webhook Secret": regexp.MustCompile(`(?i)whsec_[0-9a-zA-Z]{24}`),
	"Square OAuth Secret": regexp.MustCompile(`(?i)sq0csp-[0-9A-Za-z\-_]{43}`),
	"Telegram Bot API Key": regexp.MustCompile(`(?i)[0-9]+:AA[0-9A-Za-z\-_]{33}`),
	"Twilio Account SID": regexp.MustCompile(`(?i)AC[0-9a-fA-F]{32}`),
	"Twilio Auth Token": regexp.MustCompile(`(?i)TW[0-9a-fA-F]{32}`),
	"Github Auth Creds": regexp.MustCompile(`(?i)https://[a-zA-Z0-9]{40}@github\.com`),
	"Google Gmail API Key": regexp.MustCompile(`(?i)AIza[0-9A-Za-z\-_]{35}`),
	"Google Gmail OAuth": regexp.MustCompile(`(?i)[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
	"Google OAuth Access Token": regexp.MustCompile(`(?i)ya29\.[0-9A-Za-z\-_]+`),
	"Google YouTube API Key": regexp.MustCompile(`(?i)AIza[0-9A-Za-z\-_]{35}`),
	"Google YouTube OAuth": regexp.MustCompile(`(?i)[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
	"Twitter OAuth": regexp.MustCompile(`(?i)(twitter.*['"][0-9a-z]{35,44}['"]|https:\/\/[0-9a-z]{40}@(api\.)?twitter\.com(\/2(\/[1-9]|\/10)?)?)`),
	"Apr1 MD5": regexp.MustCompile(`(?i)\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}`),
	"MD5": regexp.MustCompile(`(?i)[a-f0-9]{32}`),
	"MD5 or SHA1": regexp.MustCompile(`(?i)[a-f0-9]{32}|[a-f0-9]{40}`),
	"SHA1": regexp.MustCompile(`(?i)[a-f0-9]{40}`),
	"SHA256": regexp.MustCompile(`(?i)[a-f0-9]{64}`),
	"SHA512": regexp.MustCompile(`(?i)[a-f0-9]{128}`),
	"MD5 or SHA1 or SHA256": regexp.MustCompile(`(?i)[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}`),
	"MD5 or SHA1 or SHA256 or SHA512": regexp.MustCompile(`(?i)[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}`),
	"Apache SHA": regexp.MustCompile(`(?i)\{SHA\}[0-9a-zA-Z/_=]{10,}`),
	"IP V4 Address": regexp.MustCompile(`(?i)\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
	"Slack App Token": regexp.MustCompile(`(?i)\bxapp-[0-9]+-[A-Za-z0-9_]+-[0-9]+-[a-f0-9]+\b`),
	"Phone Number": regexp.MustCompile(`(?i)\b(\+\d{1,2}\s)?\(\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b`),
	"AWS Access ID": regexp.MustCompile(`(?i)\b(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}\b`),
	"MAC Address": regexp.MustCompile(`(?i)\b((([a-zA-z0-9]{2}[-:]){5}([a-zA-z0-9]{2}))|(([a-zA-z0-9]{2}:){5}([a-zA-z0-9]{2})))\b`),
	"Github Classic Personal Access Token": regexp.MustCompile(`(?i)\bghp_[A-Za-z0-9_]{36}\b`),
	"Github Fine Grained Personal Access Token": regexp.MustCompile(`(?i)\bgithub_pat_[A-Za-z0-9_]{82}\b`),
	"Github OAuth Access Token": regexp.MustCompile(`(?i)\bgho_[A-Za-z0-9_]{36}\b`),
	"Github User to Server Token": regexp.MustCompile(`(?i)\bghu_[A-Za-z0-9_]{36}\b`),
	"Github Server to Server Token": regexp.MustCompile(`(?i)\bghs_[A-Za-z0-9_]{36}\b`),
	"Stripe Key": regexp.MustCompile(`(?i)\b(?:r|s)k_(test|live)_[0-9a-zA-Z]{24}\b`),
	"Firebase Auth Domain": regexp.MustCompile(`(?i)\b([a-z0-9-]){1,30}(\.firebaseapp\.com)\b`),
	"Generic Secret Key": regexp.MustCompile(`(?i)[sS][eE][cC][rR][eE][tT]_?[kK][eE][yY].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]`),
	"Generic API Secret": regexp.MustCompile(`(?i)[aA][pP][iI]_?[sS][eE][cC][rR][eE][tT].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]`),
	"Generic OAuth": regexp.MustCompile(`(?i)[aA][pP][iI]_?[sS][eE][cC][rR][eE][tT].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]`),
	"Generic API": regexp.MustCompile(`(?i)[aA][pP][iI].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]`),
	"Generic ID": regexp.MustCompile(`(?i)[aA][pP][iI]_?[iI][dD].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]`),
	"Generic Password": regexp.MustCompile(`(?i)[aA][pP][iI]_?[pP][aA][sS][sS][wW][oO][rR][dD].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]`),
	"AWS API Key": regexp.MustCompile(`(?i)((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})`),
	"AWS MWS Auth Token": regexp.MustCompile(`(?i)amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	"password": regexp.MustCompile(`(?i)/password\s*=\s*([^\s&]+)/i`),
	"pass": regexp.MustCompile(`(?i)/pass\s*=\s*([^\s&]+)/i`),
	"pwd": regexp.MustCompile(`(?i)/pwd\s*=\s*([^\s&]+)/i`),
	"username": regexp.MustCompile(`(?i)/user(?:name)?\s*=\s*([^\s&]+)/i`),
	"email": regexp.MustCompile(`(?i)/email\s*=\s*([^\s&]+)/i`),
	"userid": regexp.MustCompile(`(?i)/user(?:id)?\s*=\s*([^\s&]+)/i`),
	"login": regexp.MustCompile(`(?i)/login\s*=\s*([^\s&]+)/i`),
	"passwd": regexp.MustCompile(`(?i)/passwd\s*=\s*([^\s&]+)/i`),
	"passcode": regexp.MustCompile(`(?i)/passcode\s*=\s*([^\s&]+)/i`),
	"pw": regexp.MustCompile(`(?i)/pw\s*=\s*([^\s&]+)/i`),
	"Adafruit API Key": regexp.MustCompile(`(?i)(?:adafruit)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Adobe Client ID (OAuth Web)": regexp.MustCompile(`(?i)(?:adobe)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Adobe Client Secret": regexp.MustCompile(`(?i)\b((p8e-)(?i)[a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Age Secret Key": regexp.MustCompile(`(?i)AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`),
	"Airtable API Key": regexp.MustCompile(`(?i)(?:airtable)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{17})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Algolia API Key": regexp.MustCompile(`(?i)(?:algolia)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Alibaba AccessKey ID": regexp.MustCompile(`(?i)\b((LTAI)(?i)[a-z0-9]{20})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Alibaba Secret Key": regexp.MustCompile(`(?i)(?:alibaba)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{30})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Asana Client ID": regexp.MustCompile(`(?i)(?:asana)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9]{16})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Asana Client Secret": regexp.MustCompile(`(?i)(?:asana)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Atlassian API token": regexp.MustCompile(`(?i)(?:atlassian|confluence|jira)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{24})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"AWS": regexp.MustCompile(`(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
	"AWS MWS Key": regexp.MustCompile(`(?i)amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	"Beamer API token": regexp.MustCompile(`(?i)(?:beamer)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(b_[a-z0-9=_\-]{44})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Bitbucket Client ID": regexp.MustCompile(`(?i)(?:bitbucket)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Bitbucket Client Secret": regexp.MustCompile(`(?i)(?:bitbucket)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Bittrex Access Key": regexp.MustCompile(`(?i)(?:bittrex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Clojars API token": regexp.MustCompile(`(?i)(CLOJARS_)[a-z0-9]{60}`),
	"Codecov Access Token": regexp.MustCompile(`(?i)(?:codecov)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Coinbase Access Token": regexp.MustCompile(`(?i)(?:coinbase)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Confluent Access Token": regexp.MustCompile(`(?i)(?:confluent)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{16})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Confluent Secret Key": regexp.MustCompile(`(?i)(?:confluent)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Contentful Delivery API Token": regexp.MustCompile(`(?i)(?:contentful)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{43})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Databricks API Token": regexp.MustCompile(`(?i)\b(dapi[a-h0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Datadog Access Token": regexp.MustCompile(`(?i)(?:datadog)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"DigitalOcean OAuth Access Token": regexp.MustCompile(`(?i)\b(doo_v1_[a-f0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"DigitalOcean Personal Access Token": regexp.MustCompile(`(?i)\b(dop_v1_[a-f0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"DigitalOcean OAuth Refresh Token": regexp.MustCompile(`(?i)\b(dor_v1_[a-f0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Discord API Key": regexp.MustCompile(`(?i)(?:discord)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Discord Client ID": regexp.MustCompile(`(?i)(?:discord)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9]{18})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Discord Client Secret": regexp.MustCompile(`(?i)(?:discord)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Doppler API Token": regexp.MustCompile(`(?i)(dp\.pt\.)(?i)[a-z0-9]{43}`),
	"DroneCI Access Token": regexp.MustCompile(`(?i)(?:droneci)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Dropbox API Secret": regexp.MustCompile(`(?i)(?:dropbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{15})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Dropbox Long-Lived API Token": regexp.MustCompile(`(?i)(?:dropbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Dropbox Short-Lived API Token": regexp.MustCompile(`(?i)(?:dropbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(sl\.[a-z0-9=_\-]{135})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Duffel API Token": regexp.MustCompile(`(?i)duffel_(test|live)_(?i)[a-z0-9_=\-]{43}`),
	"Dynatrace API Token": regexp.MustCompile(`(?i)dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}`),
	"EasyPost API Token": regexp.MustCompile(`(?i)EZAK(?i)[a-z0-9]{54}`),
	"EasyPost Test API Token": regexp.MustCompile(`(?i)EZTK(?i)[a-z0-9]{54}`),
	"Etsy Access Token": regexp.MustCompile(`(?i)(?:etsy)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{24})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Facebook API Key": regexp.MustCompile(`(?i)(?:facebook)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Fastly API Key": regexp.MustCompile(`(?i)(?:fastly)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"GitHub App Token": regexp.MustCompile(`(?i)(gh(?:u|s|o|p|r)_[0-9a-z]{36}|github_pat_[0-9a-z_]{82}|glptt-[0-9a-f]{40}|GR1348941[0-9a-z\-_]{20})`),
	"Gitter Access Token": regexp.MustCompile(`(?i)(?:gitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"GoCardless API Token": regexp.MustCompile(`(?i)(?:gocardless)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(live_(?i)[a-z0-9\-_=]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Grafana api key (or Grafana cloud api key)": regexp.MustCompile(`(?i)\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,2})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Grafana cloud api token": regexp.MustCompile(`(?i)\b(glc_[A-Za-z0-9+/]{32,400}={0,2})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Grafana service account token": regexp.MustCompile(`(?i)\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"HashiCorp Terraform user/org API Token": regexp.MustCompile(`(?i)[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}`),
	"HubSpot API Token": regexp.MustCompile(`(?i)(?:hubspot)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Intercom API Token": regexp.MustCompile(`(?i)(?:intercom)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{60})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Kraken Access Token": regexp.MustCompile(`(?i)(?:kraken)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9\/=_\+\-]{80,90})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Kucoin Access Token": regexp.MustCompile(`(?i)(?:kucoin)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{24})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Kucoin Secret Key": regexp.MustCompile(`(?i)(?:kucoin)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Launchdarkly Access Token": regexp.MustCompile(`(?i)(?:launchdarkly)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Linear API Token": regexp.MustCompile(`(?i)lin_api_(?i)[a-z0-9]{40}`),
	"Linear Client Secret": regexp.MustCompile(`(?i)(?:linear)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([a-f0-9]{32})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Lob API Key": regexp.MustCompile(`(?i)(?:lob)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}((live|test)_[a-f0-9]{35})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Lob Publishable API Key": regexp.MustCompile(`(?i)(?:lob)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}((test|live)_pub_[a-f0-9]{31})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Mailgun Private API Token": regexp.MustCompile(`(?i)(?:mailgun)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}(key-[a-f0-9]{32})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Mailgun Public Validation Key": regexp.MustCompile(`(?i)(?:mailgun)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}(pubkey-[a-f0-9]{32})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Mailgun Webhook Signing Key": regexp.MustCompile(`(?i)(?:mailgun)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"MapBox API Token": regexp.MustCompile(`(?i)(?:mapbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}(pk\.[a-z0-9]{60}\.[a-z0-9]{22})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Mattermost Access Token": regexp.MustCompile(`(?i)(?:mattermost)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([a-z0-9]{26})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"MessageBird API Token": regexp.MustCompile(`(?i)(?:messagebird|message-bird|message_bird)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([a-z0-9]{25})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"MessageBird Client ID": regexp.MustCompile(`(?i)(?:messagebird|message-bird|message_bird)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Microsoft Teams Webhook": regexp.MustCompile(`(?i)https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}`),
	"Netlify Access Token": regexp.MustCompile(`(?i)(?:netlify)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([a-z0-9=_\-]{40,46})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"New Relic ingest browser API token": regexp.MustCompile(`(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}(NRJS-[a-f0-9]{19})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"New Relic user API ID": regexp.MustCompile(`(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([a-z0-9]{64})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"New Relic user API Key": regexp.MustCompile(`(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}(NRAK-[a-z0-9]{27})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"npm access token": regexp.MustCompile(`(?i)\b(npm_[a-z0-9]{36})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Nytimes Access Token": regexp.MustCompile(`(?i)(?:nytimes|new-york-times|newyorktimes)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([a-z0-9=_\-]{32})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Okta Access Token": regexp.MustCompile(`(?i)(?:okta)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([a-z0-9=_\-]{42})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Plaid API Token": regexp.MustCompile(`(?i)(?:plaid)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Plaid Client ID": regexp.MustCompile(`(?i)(?:plaid)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([a-z0-9]{24})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Plaid Secret key": regexp.MustCompile(`(?i)(?:plaid)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([a-z0-9]{30})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"PlanetScale API token": regexp.MustCompile(`(?i)\b(pscale_tkn_(?i)[a-z0-9=\-_\.]{32,64})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"PlanetScale OAuth token": regexp.MustCompile(`(?i)\b(pscale_oauth_(?i)[a-z0-9=\-_\.]{32,64})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"PlanetScale password": regexp.MustCompile(`(?i)\b(pscale_pw_(?i)[a-z0-9=\-_\.]{32,64})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Postman API token": regexp.MustCompile(`(?i)\b(PMAK-(?i)[a-f0-9]{24}-[a-f0-9]{34})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Prefect API token": regexp.MustCompile(`(?i)\b(pnu_[a-z0-9]{36})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Pulumi API token": regexp.MustCompile(`(?i)\b(pul-[a-f0-9]{40})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"PyPI upload token": regexp.MustCompile(`(?i)pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}`),
	"RapidAPI Access Token": regexp.MustCompile(`(?i)(?:rapidapi)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([a-z0-9_-]{50})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Readme API token": regexp.MustCompile(`(?i)\b(rdme_[a-z0-9]{70})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Rubygem API token": regexp.MustCompile(`(?i)\b(rubygems_[a-f0-9]{48})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Sendbird Access ID": regexp.MustCompile(`(?i)(?:sendbird)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Sendbird Access Token": regexp.MustCompile(`(?i)(?:sendbird)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([a-f0-9]{40})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"SendGrid API token": regexp.MustCompile(`(?i)\b(SG\.(?i)[a-z0-9=_\-\.]{66})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Sendinblue API token": regexp.MustCompile(`(?i)\b(xkeysib-[a-f0-9]{64}-(?i)[a-z0-9]{16})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Sentry Access Token": regexp.MustCompile(`(?i)(?:sentry)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([a-f0-9]{64})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Shippo API token": regexp.MustCompile(`(?i)\b(shippo_(live|test)_[a-f0-9]{40})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Shopify access token": regexp.MustCompile(`(?i)shpat_[a-fA-F0-9]{32}`),
	"Shopify custom access token": regexp.MustCompile(`(?i)shpca_[a-fA-F0-9]{32}`),
	"Shopify private app access token": regexp.MustCompile(`(?i)shppa_[a-fA-F0-9]{32}`),
	"Shopify shared secret": regexp.MustCompile(`(?i)shpss_[a-fA-F0-9]{32}`),
	"Sidekiq Secret": regexp.MustCompile(`(?i)(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([a-f0-9]{8}:[a-f0-9]{8})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Sidekiq Sensitive URL": regexp.MustCompile(`(?i)\b(http(?:s??):\/\/)([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\/|\#|\?|:]|$)`),
	"Slack token": regexp.MustCompile(`(?i)xox[baprs]-([0-9a-zA-Z]{10,48})`),
	"Squarespace Access Token": regexp.MustCompile(`(?i)(?:squarespace)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Stripe": regexp.MustCompile(`(?i)(sk|pk)_(test|live)_[0-9a-z]{10,32}`),
	"SumoLogic Access ID": regexp.MustCompile(`(?i)(?:sumo)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([a-z0-9]{14})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"SumoLogic Access Token": regexp.MustCompile(`(?i)(?:sumo)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([a-z0-9]{64})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"Telegram Bot API Token": regexp.MustCompile(`(?i)(?:^|[^0-9])([0-9]{5,16}:A[a-zA-Z0-9_\-]{34})(?:$|[^a-zA-Z0-9_\-])`),
	"Travis CI Access Token": regexp.MustCompile(`(?i)(?:travis)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\\"|\s|=|\x60){0,5}([a-z0-9]{22})(?:['|\\"|\n|\r|\s|\x60|;]|$)`),
	"amazon_aws_url2": regexp.MustCompile(`(?i)(?:[a-zA-Z0-9-._]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-._]+|s3-[a-zA-Z0-9-._/]+|s3\.amazonaws\.com/[a-zA-Z0-9-._]+|s3\.console\.aws\.amazon\.com/s3/buckets/[a-zA-Z0-9-._]+)`),
	"Faster_api_key": regexp.MustCompile(`(?i)\"x-fstr-application-key\"\s*:\s*\"[a-f0-9-]{36}\"`),
	"CLEARSALE_APP_ID": regexp.MustCompile(`(?i)CLEARSALE_APP_ID\s*:\s*\"([a-zA-Z0-9]+)\"`),
	"CYBERSOURCE_APP_ID": regexp.MustCompile(`(?i)CYBERSOURCE_APP_ID\s*:\s*\"([a-zA-Z0-9]+)\"`),
	"SENDBIRD_APP_ID": regexp.MustCompile(`(?i)SENDBIRD_APP_ID\s*:\s*\"([a-zA-Z0-9-]+)\"`),
	"BUGSNAG_API_KEY": regexp.MustCompile(`(?i)BUGSNAG_API_KEY\s*:\s*\"([a-f0-9]{32})\"`),  
	"GOOGLE_AUTH_KEY": regexp.MustCompile(`(?i)GOOGLE_AUTH_KEY\s*:\s*\"([a-zA-Z0-9.-_]+)\"`),
	"GOOGLE_ANALYTICS_ID": regexp.MustCompile(`(?i)GOOGLE_ANALYTICS_ID\s*:\s*\"(UA-[0-9-]+)\"`),
	"GOOGLE_TAG_MANAGER_ID": regexp.MustCompile(`(?i)GOOGLE_TAG_MANAGER_ID\s*:\s*\"(GTM-[A-Z0-9]+)\"`),
	"GOOGLE_OPTIMIZE_ID": regexp.MustCompile(`(?i)GOOGLE_OPTIMIZE_ID\s*:\s*\"(GTM-[A-Z0-9]+)\"`),
	"ADDRESS_X_APPLICATION_KEY": regexp.MustCompile(`(?i)ADDRESS_X_APPLICATION_KEY\s*:\s*\"([a-zA-Z0-9]+)\"`),
	"FACEBOOK_APP_ID": regexp.MustCompile(`(?i)FACEBOOK_APP_ID\s*:\s*\"([0-9]+)\"`),
	"FASTER_APP_KEY": regexp.MustCompile(`(?i)FASTER_APP_KEY\s*:\s*\"([a-zA-Z0-9-]+)\"`),
	"FASTER_SECRET_KEY": regexp.MustCompile(`(?i)FASTER_SECRET_KEY\s*:\s*\"([a-zA-Z0-9-]+)\"`),
	"Possible Leak - Netlify API Key": regexp.MustCompile(`(?i)[\"']?netlify[-]?api[-]?key[\"']?[^\S\r\n][=:][^\S\r\n][\"']?[\w-]+[\"']?`),
	"Possible Leak - Native Events": regexp.MustCompile(`(?i)[\"']?nativeevents[\"']?[^\S\r\n][=:][^\S\r\n][\"']?[\w-]+[\"']?`),
	"Possible Leak - MySQL Leaks": regexp.MustCompile(`(?i)["']?mysql(?:secret|masteruser|[-_]?username|[-_]?user|[-_]?root[-_]?password|[-_]?password|[-_]?hostname|[-_]?database)["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - My Secret Env": regexp.MustCompile(`(?i)[\"']?my[-]?secret[-]?env[\"']?[^\S\r\n][=:][^\S\r\n][\"']?[\w-]+[\"']?`),
	"Possible Leak - Multi Leaks": regexp.MustCompile(`(?i)["']?multi[-_]?(?:workspace|workflow|disconnect|connect)[-_]?sid["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - MinIO Secret Key": regexp.MustCompile(`(?i)[\"']?minio[-]?secret[-]?key[\"']?[^\S\r\n][=:][^\S\r\n][\"']?[\w-]+[\"']?`),
	"Possible Leak - MinIO Access Key": regexp.MustCompile(`(?i)[\"']?minio[-]?access[-]?key[\"']?[^\S\r\n][=:][^\S\r\n][\"']?[\w-]+[\"']?`),
	"Possible Leak - Mile Zero Key": regexp.MustCompile(`(?i)[\"']?mile[-]?zero[-]?key[\"']?[^\S\r\n][=:][^\S\r\n][\"']?[\w-]+[\"']?`),
	"Possible Leak - MH Leaks": regexp.MustCompile(`(?i)["']?(?:mh[_-]?(?:password|apikey)|mg[-_]?public[-_]?api[_-]?key|mg[-_]?api[-_]?key)["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Mapbox Leaks": regexp.MustCompile(`(?i)["']?mapbox(?:accesstoken|[-_]?aws[-_]?secret[-_]?access[-_]?key|[-_]?aws[-_]?access[-_]?key[-_]?id|[-_]?api[-_]?token|[-_]?access[-_]?token)["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Manifest App URL": regexp.MustCompile(`(?i)[\"']?manifest[-]?app[-]?url[\"']?[^\S\r\n][=:][^\S\r\n][\"']?[\w-]+[\"']?`),
	"Possible Leak - Manifest App Token": regexp.MustCompile(`(?i)[\"']?manifest[-]?app[-]?token[\"']?[^\S\r\n][=:][^\S\r\n][\"']?[\w-]+[\"']?`),
	"Possible Leak - Mandrill API Key": regexp.MustCompile(`(?i)[\"']?mandrill[-]?api[-]?key[\"']?[^\S\r\n][=:][^\S\r\n][\"']?[\w-]+[\"']?`),
	"Possible Leak - Management API Access Token": regexp.MustCompile(`(?i)[\"']?managementapiaccesstoken[\"']?[^\S\r\n][=:][^\S\r\n][\"']?[\w-]+[\"']?`),
	"Possible Leak - Management Token": regexp.MustCompile(`(?i)[\"']?management[_-]?token[\"']?[^\S\r\n][=:][^\S\r\n][\"']?[\w-]+[\"']?`),
	"Possible Leak - Manage Secret": regexp.MustCompile(`(?i)[\"']?manage[_-]?secret[\"']?[^\S\r\n][=:][^\S\r\n][\"']?[\w-]+[\"']?`),
	"Possible Leak - Manage Key": regexp.MustCompile(`(?i)[\"']?manage[_-]?key[\"']?[^\S\r\n][=:][^\S\r\n][\"']?[\w-]+[\"']?`),
	"Possible Leak - Mailgun Leaks_1": regexp.MustCompile(`(?i)["']?mailgun(?:[-_]?secret[-_]?api[_-]?key|[-_]?pub[-_]?key|[_-]?api[_-]?key[_-]?pub|[-_]?priv[-_]?key|[_-]?password|[_-]?apikey|[_-]?api[_-]?key[_-]?apikey|[_-]?api[_-]?key[_-]?access[_-]?key|[_-]?api[_-]?key[_-]?access[_-]?api[_-]?key)["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Mailchimp Leaks_1": regexp.MustCompile(`(?i)["']?mailchimp[_-]?apikey(?:[_-]?apikey|[_-]?access[_-]?key|[_-]?access[_-]?api[_-]?key)?["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Mail Leaks": regexp.MustCompile(`(?i)["']?mail[-_]?(?:sender[-_]?key|password|api[-_]?key|access[-_]?key|apikey)["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Magic Token": regexp.MustCompile(`(?i)[\"']?magic[_-]?token[\"']?[^\S\r\n][=:][^\S\r\n][\"']?[\w-]+[\"']?`),
	"Possible Leak - Magic Link Token": regexp.MustCompile(`(?i)[\"']?magic[-]?link[-]?token[\"']?[^\S\r\n][=:][^\S\r\n][\"']?[\w-]+[\"']?`),
	"Possible Leak - Magento Leaks": regexp.MustCompile(`(?i)["']?magento[_-]?(?:token|password|apikey|api[-_]?key)["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Magic Leaks":  regexp.MustCompile(`(?i)["']?magic[-_]?(?:secret(?:[-_]?token|[-_]?key)?|access[-_]?token|access[-_]?key|apikey)["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Mailgun Leaks_2":regexp.MustCompile(`(?i)["']?mailgun[_-]?(?:api[_-]?key[_-]?(?:priv|password)|access[_-]?(?:pub[_-]?key|priv[_-]?key|token))["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Mailchimp Leaks_2": regexp.MustCompile(`(?i)["']?mailchimp[_-]?(?:apikey[_-]?(?:pub|priv|password)|access[_-]?(?:pub[_-]?key|priv[_-]?key|token))["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Mailer Leaks": regexp.MustCompile(`(?i)["']?mailer[_-]?(?:key|token|access[_-]?(?:token|key|api[_-]?key))["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Use SSH": regexp.MustCompile(`(?i)[\"']?use[_-]?ssh[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - AWS ELB US-East-1": regexp.MustCompile(`(?i)[\"']?us[_-]?east[_-]?1[_-]?elb[_-]?amazonaws[_-]?com[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Urban Secret": regexp.MustCompile(`(?i)[\"']?urban[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Urban Master Secret": regexp.MustCompile(`(?i)[\"']?urban[_-]?master[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Urban Key": regexp.MustCompile(`(?i)[\"']?urban[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Unity Serial": regexp.MustCompile(`(?i)[\"']?unity[_-]?serial[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Unity Password": regexp.MustCompile(`(?i)[\"']?unity[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Twitter Leaks": regexp.MustCompile(`(?i)["']?twitter(?:oauthaccesstoken|oauthaccesssecret|[_-]?consumer[_-]?(?:secret|key))["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - VSCE Token": regexp.MustCompile(`(?i)[\"']?vscetoken[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Visual Recognition API Key": regexp.MustCompile(`(?i)[\"']?visual[_-]?recognition[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - VirusTotal API Key": regexp.MustCompile(`(?i)[\"']?virustotal[_-]?apikey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - VIP GitHub Deploy Key Password": regexp.MustCompile(`(?i)[\"']?vip[_-]?github[_-]?deploy[_-]?key[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - VIP GitHub Deploy Key": regexp.MustCompile(`(?i)[\"']?vip[_-]?github[_-]?deploy[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - VIP GitHub Build Repo Deploy Key": regexp.MustCompile(`(?i)[\"']?vip[_-]?github[_-]?build[_-]?repo[_-]?deploy[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Salesforce Password": regexp.MustCompile(`(?i)[\"']?v[_-]?sfdc[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Salesforce Client Secret": regexp.MustCompile(`(?i)[\"']?v[_-]?sfdc[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - User Travis": regexp.MustCompile(`(?i)[\"']?usertravis[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - User Assets Secret Access Key": regexp.MustCompile(`(?i)[\"']?user[_-]?assets[_-]?secret[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - User Assets Access Key ID": regexp.MustCompile(`(?i)[\"']?user[_-]?assets[_-]?access[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Widget Leaks":regexp.MustCompile(`(?i)["']?widget[_-]?(?:test[_-]?server|fb[_-]?password(?:[_-]?[23])?|basic[_-]?password(?:[_-]?[2345])?)["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Widget Basic Password": regexp.MustCompile(`(?i)[\"']?widget[_-]?basic[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Watson Password": regexp.MustCompile(`(?i)[\"']?watson[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Watson Device Password": regexp.MustCompile(`(?i)[\"']?watson[_-]?device[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Watson Conversation Password": regexp.MustCompile(`(?i)[\"']?watson[_-]?conversation[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - WakaTime API Key": regexp.MustCompile(`(?i)[\"']?wakatime[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Sonar Token": regexp.MustCompile(`(?i)[\"']?sonar[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Sonar Project Key": regexp.MustCompile(`(?i)[\"']?sonar[_-]?project[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Sonar Organization Key": regexp.MustCompile(`(?i)[\"']?sonar[_-]?organization[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Socrata Password": regexp.MustCompile(`(?i)[\"']?socrata[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Socrata App Token": regexp.MustCompile(`(?i)[\"']?socrata[_-]?app[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Snyk Token": regexp.MustCompile(`(?i)[\"']?snyk[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Snyk API Token": regexp.MustCompile(`(?i)[\"']?snyk[_-]?api[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - WPJM PHPUnit Google Geocode API Key": regexp.MustCompile(`(?i)[\"']?wpjm[_-]?phpunit[_-]?google[_-]?geocode[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - WordPress DB User": regexp.MustCompile(`(?i)[\"']?wordpress[_-]?db[_-]?user[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - WordPress DB Password": regexp.MustCompile(`(?i)[\"']?wordpress[_-]?db[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - WinCert Password": regexp.MustCompile(`(?i)[\"']?wincert[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Spotify API Client Secret": regexp.MustCompile(`(?i)[\"']?spotify[_-]?api[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Spotify API Access Token": regexp.MustCompile(`(?i)[\"']?spotify[_-]?api[_-]?access[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Spaces Secret Access Key": regexp.MustCompile(`(?i)[\"']?spaces[_-]?secret[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Spaces Access Key ID": regexp.MustCompile(`(?i)[\"']?spaces[_-]?access[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - SoundCloud Password": regexp.MustCompile(`(?i)[\"']?soundcloud[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - SoundCloud Client Secret": regexp.MustCompile(`(?i)[\"']?soundcloud[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Sonatype Leaks": regexp.MustCompile(`(?i)["']?sonatype[_-]?(?:password|token[_-]?(?:user|password)|pass|nexus[_-]?password|gpg[_-]?(?:passphrase|key[_-]?name))["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Starship Auth Token": regexp.MustCompile(`(?i)[\"']?starship[_-]?auth[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Starship Account SID": regexp.MustCompile(`(?i)[\"']?starship[_-]?account[_-]?sid[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Star Leaks": regexp.MustCompile(`(?i)["']?star[_-]?test[_-]?(?:secret[_-]?access[_-]?key|location|bucket|aws[_-]?access[_-]?key[_-]?id)["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Staging Base URL Runscope": regexp.MustCompile(`(?i)[\"']?staging[_-]?base[_-]?url[_-]?runscope[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - SSMTP Config": regexp.MustCompile(`(?i)[\"']?ssmtp[_-]?config[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - SSHPass": regexp.MustCompile(`(?i)[\"']?sshpass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - SrcClr API Token": regexp.MustCompile(`(?i)[\"']?srcclr[_-]?api[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Square Reader SDK Repository Password": regexp.MustCompile(`(?i)[\"']?square[_-]?reader[_-]?sdk[_-]?repository[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - SQS Secret Key": regexp.MustCompile(`(?i)[\"']?sqssecretkey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - SQS Access Key": regexp.MustCompile(`(?i)[\"']?sqsaccesskey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Spring Mail Password": regexp.MustCompile(`(?i)[\"']?spring[_-]?mail[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Tester Keys Password": regexp.MustCompile(`(?i)[\"']?tester[_-]?keys[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Test Test": regexp.MustCompile(`(?i)[\"']?test[_-]?test[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Test GitHub Token": regexp.MustCompile(`(?i)[\"']?test[_-]?github[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Tesco API Key": regexp.MustCompile(`(?i)[\"']?tesco[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - SVN Password": regexp.MustCompile(`(?i)[\"']?svn[_-]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Surge Token": regexp.MustCompile(`(?i)[\"']?surge[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Surge Login": regexp.MustCompile(`(?i)[\"']?surge[_-]?login[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Stripe Leaks": regexp.MustCompile(`(?i)["']?stripe[_-]?(?:public|private|secret[_-]?key|publishable[_-]?key)["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Stormpath API Key Secret": regexp.MustCompile(`(?i)[\"']?stormpath[_-]?api[_-]?key[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Stormpath API Key ID": regexp.MustCompile(`(?i)[\"']?stormpath[_-]?api[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - LinkedIn Leaks": regexp.MustCompile(`(?i)["']?linkedin[_-]?(?:secret[_-]?(?:id|secret|api[_-]?key[_-]?(?:id|priv[_-]?key))|token[_-]?(?:id|secret|api[_-]?key[_-]?id|api[_-]?key[_-]?priv[_-]?key|auth[_-]?token)|auth[_-]?(?:id|secret|api[_-]?key[_-]?id))["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Azure Leaks": regexp.MustCompile(`(?i)["']?azure[_-]?(?:secret[_-]?(?:id|secret|api[_-]?key[_-]?(?:id|priv[_-]?key))|token[_-]?(?:id|secret|api[_-]?key[_-]?(?:id|secret|apikey|password|token|auth[_-]?key|pub[_-]?key|priv[_-]?key))|auth[_-]?(?:id|secret|api[_-]?key[_-]?(?:id|secret|apikey|password|token|auth[_-]?key|pub[_-]?key|priv[_-]?key)))["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Twilio Leaks": regexp.MustCompile(`(?i)["']?twilio[_-]?(?:token|sid|configuration[_-]?sid|chat[_-]?account[_-]?api[_-]?service|api[_-]?(?:secret|key))["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Trex Okta Client Token": regexp.MustCompile(`(?i)[\"']?trex[_-]?okta[_-]?client[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Trex Client Token": regexp.MustCompile(`(?i)[\"']?trex[_-]?client[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Travis Leaks": regexp.MustCompile(`(?i)["']?travis[_-]?(?:token|secure[_-]?env[_-]?vars|pull[_-]?request|gh[_-]?token|e2e[_-]?token|com[_-]?token|branch|api[_-]?token|access[_-]?token)["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Token Core Java": regexp.MustCompile(`(?i)[\"']?token[_-]?core[_-]?java[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Thera OSS Access Key": regexp.MustCompile(`(?i)[\"']?thera[_-]?oss[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Secret Key": regexp.MustCompile(`(?i)[\"']?secretkey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Secret Access Key": regexp.MustCompile(`(?i)[\"']?secretaccesskey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Secret Key Base": regexp.MustCompile(`(?i)[\"']?secret[_-]?key[_-]?base[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Secrets 1-10": regexp.MustCompile(`(?i)["']?secret[_-]?(?:0?[0-9]|10|11)["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - SDR Token": regexp.MustCompile(`(?i)[\"']?sdr[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Scrutinizer Token": regexp.MustCompile(`(?i)[\"']?scrutinizer[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Sauce Access Key": regexp.MustCompile(`(?i)[\"']?sauce[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Sandbox AWS Secret Access Key": regexp.MustCompile(`(?i)[\"']?sandbox[_-]?aws[_-]?secret[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Sandbox AWS Access Key ID": regexp.MustCompile(`(?i)[\"']?sandbox[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Twine Password": regexp.MustCompile(`(?i)[\"']?twine[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Sentry Leaks": regexp.MustCompile(`(?i)["']?sentry[_-]?(?:key|secret|endpoint|default[_-]?org|auth[_-]?token)["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - SendWithUs Key": regexp.MustCompile(`(?i)[\"']?sendwithus[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - SendGrid Leaks": regexp.MustCompile(`(?i)["']?sendgrid(?:[_-]?(?:username|user|password|key|api[_-]?key))?["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Selion Selenium Host": regexp.MustCompile(`(?i)[\"']?selion[_-]?selenium[_-]?host[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Selion Log Level Dev": regexp.MustCompile(`(?i)[\"']?selion[_-]?log[_-]?level[_-]?dev[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Segment API Key": regexp.MustCompile(`(?i)[\"']?segment[_-]?api[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Snoowrap Refresh Token": regexp.MustCompile(`(?i)[\"']?snoowrap[_-]?refresh[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Snoowrap Password": regexp.MustCompile(`(?i)[\"']?snoowrap[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Snoowrap Client Secret": regexp.MustCompile(`(?i)[\"']?snoowrap[_-]?client[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Slate User Email": regexp.MustCompile(`(?i)[\"']?slate[_-]?user[_-]?email[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Slash Developer Space Key": regexp.MustCompile(`(?i)[\"']?slash[_-]?developer[_-]?space[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Slash Developer Space": regexp.MustCompile(`(?i)[\"']?slash[_-]?developer[_-]?space[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Signing Key SID": regexp.MustCompile(`(?i)["']?signing[_-]?key(?:[_-]?(sid|secret|password))?["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Set Secret Key": regexp.MustCompile(`(?i)[\"']?setsecretkey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Set DST Secret Key": regexp.MustCompile(`(?i)[\"']?setdstsecretkey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Set DST Access Key": regexp.MustCompile(`(?i)[\"']?setdstaccesskey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - SES Secret Key": regexp.MustCompile(`(?i)[\"']?ses[_-]?secret[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - SES Access Key": regexp.MustCompile(`(?i)[\"']?ses[_-]?access[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Service Account Secret": regexp.MustCompile(`(?i)[\"']?service[_-]?account[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Password Leaks": regexp.MustCompile(`(?i)["']?password(?:[_-]?(?:postgres|private|prod[_-]?private?|preview|pypi|publish|qld|pub|priv|pr(?:[_-]?live)?|preprod(?:[_-]?secret)?|p4|p2|p1|p(?:[_-]?mail)?|os[_-]?aerogear|opensource|oauth(?:[_-]?token)?|o|myweb|mygit|my[_-]?github|my[_-]?git|migrations|mc4|key|jwt|jira))?["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - PyPI Password": regexp.MustCompile(`(?i)[\"']?pypi[-_]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Pushover Token": regexp.MustCompile(`(?i)[\"']?pushover[-_]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Pushover User": regexp.MustCompile(`(?i)[\"']?pushover[-_]?user[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Pusher App Secret": regexp.MustCompile(`(?i)[\"']?pusher[-_]?app[-_]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - PubNub Leaks": regexp.MustCompile(`(?i)["']?pubnub[-_]?(?:subscribe|secret|publish|cipher|auth)[-_]?key["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Prometheus Token": regexp.MustCompile(`(?i)[\"']?prometheus[-_]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Private Key Token": regexp.MustCompile(`(?i)[\"']?private[-_]?key[-_]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Prismic Token": regexp.MustCompile(`(?i)[\"']?prismic[-_]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Private Key ID": regexp.MustCompile(`(?i)[\"']?private[-_]?key[-_]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Project Key": regexp.MustCompile(`(?i)[\"']?project[-_]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Prod Deploy Key": regexp.MustCompile(`(?i)[\"']?prod[-_]?deploy[-_]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Private Key": regexp.MustCompile(`(?i)[\"']?private[-_]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Pivotal Tracker Token": regexp.MustCompile(`(?i)[\"']?pivotal[-_]?tracker[-_]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Personal Access Token": regexp.MustCompile(`(?i)[\"']?personal[-_]?access[-_]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Password Token": regexp.MustCompile(`(?i)[\"']?password[-_]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - PayPal Client Secret": regexp.MustCompile(`(?i)[\"']?paypal[-_]?client[-_]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - PayPal Client ID": regexp.MustCompile(`(?i)[\"']?paypal[-_]?client[-_]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Path To File": regexp.MustCompile(`(?i)[\"']?path[-_]?to[-_]?file[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Passwd S3 Access Key": regexp.MustCompile(`(?i)[\"']?passwd[-_]?s3[-_]?access[-_]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Passwd S3 Secret Key": regexp.MustCompile(`(?i)[\"']?passwd[-_]?s3[-_]?secret[-_]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Password To Leaks": regexp.MustCompile(`(?i)["']?password(?:[-_]?to(?:[-_]?jenkins|[-_]?file|[-_]?azure[-_]?file)?|[-_]?test|[-_]?storj|[-_]?staging|[-_]?stage|[-_]?slack|[-_]?secret|[-_]?s3|[-_]?repo|[-_]?rds)?["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Repo Token": regexp.MustCompile(`(?i)[\"']?repotoken[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Reporting WebDav URL": regexp.MustCompile(`(?i)[\"']?reporting[-_]?webdav[-_]?url[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Reporting WebDav Password": regexp.MustCompile(`(?i)[\"']?reporting[-_]?webdav[-_]?pwd[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Release Token": regexp.MustCompile(`(?i)[\"']?release[-_]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Release GitHub Token": regexp.MustCompile(`(?i)[\"']?release[-_]?gh[-_]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Registry Secure": regexp.MustCompile(`(?i)[\"']?registry[-_]?secure[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Registry Password": regexp.MustCompile(`(?i)[\"']?registry[-_]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Refresh Token": regexp.MustCompile(`(?i)[\"']?refresh[-_]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - RedisCloud URL": regexp.MustCompile(`(?i)[\"']?rediscloud[-_]?url[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Redis Stunnel URLs": regexp.MustCompile(`(?i)[\"']?redis[-_]?stunnel[-_]?urls[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Randr Music API Access Token": regexp.MustCompile(`(?i)[\"']?randrmusicapiaccesstoken[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - RabbitMQ Password": regexp.MustCompile(`(?i)[\"']?rabbitmq[-_]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Quip Token": regexp.MustCompile(`(?i)[\"']?quip[-_]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Qiita Token": regexp.MustCompile(`(?i)[\"']?qiita[-_]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Salesforce Bulk Test Security Token": regexp.MustCompile(`(?i)[\"']?salesforce[-_]?bulk[-_]?test[-_]?security[-_]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Salesforce Bulk Test Password": regexp.MustCompile(`(?i)[\"']?salesforce[-_]?bulk[-_]?test[-_]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - SACloud API": regexp.MustCompile(`(?i)[\"']?sacloud[-_]?api[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - SACloud Access Token Secret": regexp.MustCompile(`(?i)[\"']?sacloud[-_]?access[-_]?token[-_]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - SACloud Access Token": regexp.MustCompile(`(?i)[\"']?sacloud[-_]?access[-_]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - S3 Leaks": regexp.MustCompile(`(?i)["']?s3[-_]?(?:user[-_]?secret|secret[-_]?(?:key|assets|app[-_]?logs)|key(?:[-_]?(?:assets|app[-_]?logs))?|bucket[-_]?name[-_]?(?:assets|app[-_]?logs)|access[-_]?key(?:[-_]?id)?)["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Rubygems Auth Token": regexp.MustCompile(`(?i)[\"']?rubygems[-_]?auth[-_]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - RTD Store Pass": regexp.MustCompile(`(?i)[\"']?rtd[-_]?store[-_]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - RTD Key Pass": regexp.MustCompile(`(?i)[\"']?rtd[-_]?key[-_]?pass[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Route53 Access Key ID": regexp.MustCompile(`(?i)[\"']?route53[-_]?access[-_]?key[-_]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Ropsten Private Key": regexp.MustCompile(`(?i)[\"']?ropsten[-_]?private[-_]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Rinkeby Private Key": regexp.MustCompile(`(?i)[\"']?rinkeby[-_]?private[-_]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - REST API Key": regexp.MustCompile(`(?i)[\"']?rest[-_]?api[-_]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - YouTube API Key Token":regexp.MustCompile(`(?i)["']?youtube[_-]?(?:secret[_-]?api[_-]?key[_-]?(?:token|auth[_-]?key|pub[_-]?key|priv[_-]?key)|token[_-]?(?:id|secret|api[_-]?key[_-]?(?:id|secret|apikey)))["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Auth API Key Priv Key": regexp.MustCompile(`(?i)[\"']?twitter[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Twitter Token Auth Token": regexp.MustCompile(`(?i)[\"']?twitter[_-]?token[_-]?auth[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - GitLab Secret ID": regexp.MustCompile(`(?i)[\"']?gitlab[_-]?secret[_-]?id[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - GitLab Secret Secret": regexp.MustCompile(`(?i)[\"']?gitlab[_-]?secret[_-]?secret[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - GitLab Auth API Key Auth Key": regexp.MustCompile(`(?i)[\"']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - GitLab Auth API Key Pub Key": regexp.MustCompile(`(?i)[\"']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - GitLab Auth API Key Priv Key": regexp.MustCompile(`(?i)[\"']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - GitLab Token Auth Token": regexp.MustCompile(`(?i)[\"']?gitlab[_-]?token[_-]?auth[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Facebook Secret": regexp.MustCompile(`(?i)["']?facebook[_-]?(?:secret|token|auth)[_-]?(?:id|password|secret|token|auth[_-]?key|pub[_-]?key|priv[_-]?key)?["']?\s*[=:]\s*["']?([\w-]+)["']?`),
	"Possible Leak - Facebook API Key": regexp.MustCompile(`(?i)[\"']?facebook[_-]?api[_-]?key[_-]?(?:id|password|secret|token|auth[_-]?key|pub[_-]?key|priv[_-]?key)[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?([\w-]+)[\"']?`),
	"Possible Leak - AWS Leaks": regexp.MustCompile(`(?i)["']?aws[_-]?(?:secret[_-]?id|api[_-]?key[_-]?(?:id|secret|apikey|password|token|auth[_-]?key|pub[_-]?key|priv[_-]?key)?|token[_-]?(?:id|secret|api[_-]?key[_-]?(?:id|secret|apikey|password|token|auth[_-]?key|pub[_-]?key|priv[_-]?key)?|auth[_-]?token)?|auth[_-]?(?:id|secret|api[_-]?key[_-]?(?:id|secret|apikey|password|token|auth[_-]?key|pub[_-]?key|priv[_-]?key)?)?)["']?\s*[=:]\s*["']?([\w-]+)["']?`),
	"Amazon_Auth_ID": regexp.MustCompile(`(?i)["']?amazon[_-]?auth[_-]?(?:id|secret|api[_-]?key[_-]?(?:auth[_-]?key|pub[_-]?key|priv[_-]?key))["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - google secrets": regexp.MustCompile(`(?i)[\"']?(google[_-]?(secret|token|auth)?[_-]?(api[_-]?)?key[_-]?(id|secret|apikey|password|token|auth[_-]?key|pub[_-]?key|priv[_-]?key)?)[\"']?\s*[=:]\s*[\"']?([\w-]+)[\"']?`),
	"Possible Leak - Flask Secret Key": regexp.MustCompile(`(?i)[\"']?flask[_-]?secret[_-]?key[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Firebase API Token": regexp.MustCompile(`(?i)[\"']?firebase[_-]?api[_-]?token[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Firebase API JSON": regexp.MustCompile(`(?i)[\"']?firebase[_-]?api[_-]?json[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - File Password": regexp.MustCompile(`(?i)[\"']?file[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Exp Password": regexp.MustCompile(`(?i)[\"']?exp[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Eureka AWS Secret Key": regexp.MustCompile(`(?i)[\"']?eureka[_-]?awssecretkey[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"Possible Leak - Env Sonatype Password": regexp.MustCompile(`(?i)[\"']?env[_-]?sonatype[_-]?password[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?`),
	"AWS Access Key": regexp.MustCompile(`(?i)(A3T[A-Z0-9]|AKIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA|ASCA|APKA)[A-Z0-9]{16}`),
	"AWS Secret Key": regexp.MustCompile(`(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]`),
	"Twitch API token": regexp.MustCompile("(?i)twitch[0-9a-z_\\-\\t .]{0,20}['\"\\s]{0,3}(=|>|:=|\\|\\|:|<=|=>|:)[='\"`\\s]{0,5}([a-z0-9]{30})['\"\\n\\r\\s`;]|$"),
	"Twitter Access Secret": regexp.MustCompile("(?i)twitter[0-9a-z_\\-\\t .]{0,20}['\"\\s]{0,3}(=|>|:=|\\|\\|:|<=|=>|:)[='\"`\\s]{0,5}([a-z0-9]{45})['\"\\n\\r\\s`;]|$"),
	"Twitter Bearer Token": regexp.MustCompile("(?i)twitter[0-9a-z_\\-\\t .]{0,20}['\"\\s]{0,3}(=|>|:=|\\|\\|:|<=|=>|:)[='\"`\\s]{0,5}(A{22}[a-zA-Z0-9%]{80,100})['\"\\n\\r\\s`;]|$"),
	"Typeform API token": regexp.MustCompile("(?i)typeform[0-9a-z_\\-\\t .]{0,20}['\"\\s]{0,3}(=|>|:=|\\|\\|:|<=|=>|:)[='\"`\\s]{0,5}(tfp_[a-z0-9\\-_.]{59})['\"\\n\\r\\s`;]|$"),
	"Vault Batch Token": regexp.MustCompile("(?i)(hvb\\.[a-z0-9_-]{138,212})['\"\\n\\r\\s`;]|$"),
	"Vault Service Token": regexp.MustCompile("(?i)(hvs\\.[a-z0-9_-]{90,100})['\"\\n\\r\\s`;]|$"),
	"Yandex Access Token": regexp.MustCompile("(?i)yandex[0-9a-z_\\-\\t .]{0,20}['\"\\s]{0,3}(=|>|:=|\\|\\|:|<=|=>|:)[='\"`\\s]{0,5}(t1\\.[A-Z0-9a-z_-]+={0,2}\\.[A-Z0-9a-z_-]{86}={0,2})['\"\\n\\r\\s`;]|$"),
	"Yandex API Key": regexp.MustCompile("(?i)yandex[0-9a-z_\\-\\t .]{0,20}['\"\\s]{0,3}(=|>|:=|\\|\\|:|<=|=>|:)[='\"`\\s]{0,5}(AQVN[A-Za-z0-9_\\-]{35,38})['\"\\n\\r\\s`;]|$"),
	"Yandex AWS Access Token": regexp.MustCompile("(?i)yandex[0-9a-z_\\-\\t .]{0,20}['\"\\s]{0,3}(=|>|:=|\\|\\|:|<=|=>|:)[='\"`\\s]{0,5}(YC[a-zA-Z0-9_\\-]{38})['\"\\n\\r\\s`;]|$"),
	"Zendesk Secret Key": regexp.MustCompile("(?i)zendesk[0-9a-z_\\-\\t .]{0,20}['\"\\s]{0,3}(=|>|:=|\\|\\|:|<=|=>|:)[='\"`\\s]{0,5}([a-z0-9]{40})['\"\\n\\r\\s`;]|$"),
 	"Cloudflare API Key": regexp.MustCompile(`(?i)cloudflare[0-9a-z_\-\t .]{0,20}['"\s]{0,3}(=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)['"` + "`" + `\s=]{0,5}([a-z0-9_-]{40})['"\n\r\s` + "`" + `;]|$`),
	"Cloudflare Global API Key": regexp.MustCompile(`(?i)cloudflare[0-9a-z_\-\t .]{0,20}['"\s]{0,3}(=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)['"` + "`" + `\s=]{0,5}([a-f0-9]{37})['"\n\r\s` + "`" + `;]|$`),
	"Cloudflare Origin CA Key": regexp.MustCompile(`(?i)\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})['"\n\r\s` + "`" + `;]|$`),
	"Discord Webhook": regexp.MustCompile(`(?i)https:\\/\\/discordapp\\.com\\/api\\/webhooks\\/[0-9]+\\/[A-Za-z0-9\\-]+`),
	"Google Calendar URI": regexp.MustCompile(`(?i)https:\\/\\/(.*)calendar\\.google\\.com\\/calendar\\/[0-9a-z\\/]+\\/embed\\?src=[A-Za-z0-9%@&;=\\-_\\.\\/]+`),
	"Google OAuth Access Key": regexp.MustCompile(`(?i)ya29\\.[0-9A-Za-z\\-_]+`),
	"Mapbox Token Disclosure": regexp.MustCompile(`(?i)(pk|sk)\\.eyJ1Ijoi\\w+\\.[\\w-]*`),
	"Alibaba OSS Bucket": regexp.MustCompile(`(?i)(?:[a-zA-Z0-9-\\.\\_]+\\.oss-[a-zA-Z0-9-\\.\\_]+\\.aliyuncs\\.com|oss-[a-zA-Z0-9-\\.\\_]+\\.aliyuncs\\.com\\/[a-zA-Z0-9-\\.\\_]+)`),
	"Slack": regexp.MustCompile(`(?i)xox[baprs]-([0-9a-zA-Z]{10,48})?`),
	"Asymmetric Private Key": regexp.MustCompile(`(?i)-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----`),
}

// -------- MAIN STARTS HERE --------
func main() {
    filePath := flag.String("f", "", "Path to file containing URLs (one per line)")
    flag.Parse()

    if *filePath == "" {
        fmt.Println("Please specify a file path using -f flag")
        os.Exit(1)
    }

    urls, err := readURLs(*filePath)
    if err != nil {
        fmt.Printf("Error reading URLs: %v\n", err)
        os.Exit(1)
    }

    client := newHTTPClient(requestTimeout)

    // Warm up TCP connections for all unique hosts first
    fmt.Println("Warming up connections to hosts...")
    if err := warmupConnections(client, urls); err != nil {
        fmt.Printf("Warning: error during warmup: %v\n", err)
    }
    fmt.Println("Warmup done. Starting requests...")

    var wg sync.WaitGroup
    sem := make(chan struct{}, maxConcurrency)

    var successCount int64
    var errorCount int64

    for _, urlStr := range urls {
        wg.Add(1)
        sem <- struct{}{}

        go func(u string) {
            defer wg.Done()
            defer func() { <-sem }()

            body, status, err := fetchURL(client, u)
            if err != nil {
                fmt.Printf("[ERROR] %s - %v\n", u, err)
                atomic.AddInt64(&errorCount, 1)
                return
            }

            atomic.AddInt64(&successCount, 1)
            findings := scanFindings(body, u)

            // Print summary for this URL
            if len(findings) > 0 {
                green := "\033[32m"
                reset := "\033[0m"
                fmt.Printf("%s[+] Findings for %s (status %d):%s\n", green, u, status, reset)
                for _, finding := range findings {
                    fmt.Println(finding)
                }
                fmt.Println()
            } else {
                // Optionally print nothing for clean URLs, or:
                fmt.Printf("[OK] %s (status %d): No sensitive data found\n", u, status)
            }
        }(urlStr)
    }

    wg.Wait()

    total := len(urls)
    fmt.Printf("\nSummary: Processed %d URLs\n", total)
    fmt.Printf("Successful: %d\n", atomic.LoadInt64(&successCount))
    fmt.Printf("Errors: %d\n", atomic.LoadInt64(&errorCount))
}

// ------------- SENSITIVE DATA FINDINGS LOGIC -------------
func scanFindings(responseBody string, url string) []string {
    var findings []string
    for name, re := range regexes {
        match := re.FindString(responseBody)
        if match != "" {
            findings = append(findings, fmt.Sprintf("  - [%s] Found: %s", name, match))
        }
    }
    return findings
}

// ---------------------------------------------------------

// --- Utilities unchanged from your script below ---

func warmupConnections(client *http.Client, urls []string) error {
    uniqueHosts := make(map[string]struct{})
    for _, u := range urls {
        host, err := extractHost(u)
        if err != nil {
            continue
        }
        uniqueHosts[host] = struct{}{}
    }

    for host := range uniqueHosts {
        warmupURL := "https://" + host + "/"
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        req, err := http.NewRequestWithContext(ctx, http.MethodHead, warmupURL, nil)
        if err != nil {
            cancel()
            continue
        }
        req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; spidey/1.0)")

        resp, err := client.Do(req)
        cancel()
        if err != nil {
            fmt.Printf("[Warmup Warning] Could not connect to %s: %v\n", warmupURL, err)
            continue
        }
        io.Copy(io.Discard, resp.Body)
        resp.Body.Close()
    }
    return nil
}

func extractHost(rawurl string) (string, error) {
    u, err := url.Parse(rawurl)
    if err != nil {
        return "", err
    }
    return u.Host, nil
}

func readURLs(path string) ([]string, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    var urls []string
    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := scanner.Text()
        if line != "" {
            urls = append(urls, line)
        }
    }
    if err := scanner.Err(); err != nil {
        return nil, err
    }
    return urls, nil
}

func newHTTPClient(timeout time.Duration) *http.Client {
    return &http.Client{
        Timeout: timeout,
        Transport: &http.Transport{
            MaxIdleConns:        100,
            MaxIdleConnsPerHost: 20,
            IdleConnTimeout:     90 * time.Second,
        },
    }
}

func fetchURL(client *http.Client, url string) (string, int, error) {
    ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
    defer cancel()

    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        return "", 0, err
    }

    req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; spidey/1.0)")

    resp, err := client.Do(req)
    if err != nil {
        return "", 0, err
    }
    defer resp.Body.Close()

    // Optional: Limit size to avoid huge memory usage
    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", resp.StatusCode, err
    }

    return string(bodyBytes), resp.StatusCode, nil
}
