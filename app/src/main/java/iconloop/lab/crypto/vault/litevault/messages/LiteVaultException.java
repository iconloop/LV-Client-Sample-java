package iconloop.lab.crypto.vault.litevault.messages;

public class LiteVaultException extends Exception {

    public LiteVaultException(String message) {
        super(message);
    }

    public LiteVaultException(Throwable cause) {
        super(cause);
    }

    public LiteVaultException(String message, Throwable cause) {
        super(message, cause);
    }
}
