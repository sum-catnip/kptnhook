New-SelfSignedCertificate -Subject "kptnhook" -Type CodeSigningCert -CertStoreLocation cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(99)