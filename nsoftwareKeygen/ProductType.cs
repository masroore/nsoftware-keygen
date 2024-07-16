namespace nsoftwareKeygen;

public enum ProductType : ushort
{
    CloudStorage = 16,
    IPWorks = 98,
    IPWorksSSL = 17,
    IPWorksSFTP = 17 + 1,
    IPWorksSSH,
    IPWorksSMIME,
    IPWorksEncrypt,
    IPWorksOpenPGP,
    IPWorksSNMP = 57,
    IPWorksZip = 34,
    IPWorksAuth,
    IPWorksIPC,
    IPWorksMQ,
    IPWorksIOT,
    IPWorksEDI,
    IPWorksEDITranslator,
    IPWorksBLE,
    IPWorks3DS,
    CloudMail = 76,
    CloudKeys = 1,
    SecureBlackbox = 822
}