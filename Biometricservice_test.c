#include <stdio.h>
#include <stdlib.h>
#include <android/binder_manager.h>
#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <android/binder_status.h>

#define TRANSACTION_authenticate (IBinder_FIRST_CALL_TRANSACTION + 0)

// Receiver transaction codes
#define TRANSACTION_onAuthenticationSucceeded (IBinder_FIRST_CALL_TRANSACTION + 0)
#define TRANSACTION_onAuthenticationFailed    (IBinder_FIRST_CALL_TRANSACTION + 1)
#define TRANSACTION_onError                   (IBinder_FIRST_CALL_TRANSACTION + 2)
#define TRANSACTION_onAcquired                (IBinder_FIRST_CALL_TRANSACTION + 3)
#define TRANSACTION_onDialogDismissed         (IBinder_FIRST_CALL_TRANSACTION + 4)

static binder_status_t receiver_onTransact(AIBinder* binder,
                                           transaction_code_t code,
                                           const AParcel* in,
                                           AParcel* out) {
    switch (code) {
        case TRANSACTION_onAuthenticationSucceeded: {
            int32_t cookie;
            AParcel_readInt32(in, &cookie);
            // token is a byte array
            int32_t len;
            const void* token;
            AParcel_readByteArray(in, &token, &len);
            printf("Auth succeeded, cookie=%d, tokenLen=%d\n", cookie, len);
            break;
        }
        case TRANSACTION_onAuthenticationFailed: {
            int32_t cookie;
            AParcel_readInt32(in, &cookie);
            printf("Auth failed, cookie=%d\n", cookie);
            break;
        }
        case TRANSACTION_onError: {
            int32_t cookie, error, vendor;
            AParcel_readInt32(in, &cookie);
            AParcel_readInt32(in, &error);
            AParcel_readInt32(in, &vendor);
            printf("Error=%d vendor=%d cookie=%d\n", error, vendor, cookie);
            break;
        }
        case TRANSACTION_onAcquired: {
            int32_t cookie, acquired, vendor;
            AParcel_readInt32(in, &cookie);
            AParcel_readInt32(in, &acquired);
            AParcel_readInt32(in, &vendor);
            printf("Acquired=%d vendor=%d cookie=%d\n", acquired, vendor, cookie);
            break;
        }
        case TRANSACTION_onDialogDismissed: {
            int32_t reason;
            AParcel_readInt32(in, &reason);
            printf("Dialog dismissed, reason=%d\n", reason);
            break;
        }
        default:
            printf("Unhandled callback code=%d\n", code);
    }
    return STATUS_OK;
}

int main() {
    AIBinder* service = AServiceManager_getService("biometric");
    if (!service) {
        fprintf(stderr, "Failed to get BiometricService\n");
        return EXIT_FAILURE;
    }

    AIBinder_Class* receiverClass =
        AIBinder_Class_define("android.hardware.biometrics.IBiometricServiceReceiver",
                              receiver_onTransact);
    AIBinder* receiverBinder = AIBinder_new(receiverClass, NULL);

    AParcel* data;
    AParcel* reply;
    AIBinder_prepareTransaction(service, &data);

    AParcel_writeInterfaceToken(data, "android.hardware.biometrics.IBiometricService");
    AParcel_writeStrongBinder(data, NULL); // token binder
    AParcel_writeInt32(data, 0);           // userId
    AParcel_writeInt32(data, 1234);        // cookie
    AParcel_writeStrongBinder(data, receiverBinder);
    AParcel_writeString(data, "com.example.biometrictest");

    binder_status_t status = AIBinder_transact(service,
                                               TRANSACTION_authenticate,
                                               data,
                                               &reply,
                                               0);
    if (status != STATUS_OK) {
        fprintf(stderr, "Transaction failed: %d\n", status);
        return EXIT_FAILURE;
    }

    printf("Authenticate() call sent.\n");
    return EXIT_SUCCESS;
}
