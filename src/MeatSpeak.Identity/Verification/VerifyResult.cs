namespace MeatSpeak.Identity.Verification;

public enum VerifyResult
{
    Verified,
    Partial,
    KeyMismatch,
    NoKeyFound,
    SignatureFailed,
}
