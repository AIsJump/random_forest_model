import thrember, os
import signify.authenticode.signed_file as sas
# import sas.SignedPEFile

if __name__ == "__main__":
    print('main process:', os.getpid())
    thrember.create_vectorized_features('model_datasets')
else:
    print('other process:', os.getpid())