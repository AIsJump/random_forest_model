import thrember, sys

# LEGACY DO NOT USE!!!!!!!!!!!!!!!!!
t = sys.argv[1]

if t == '0':
    print('downloading training data')
    thrember.download_dataset('datasets', file_type='Win64', split='train')
    print('finished')
elif t == '1':
    print('downloading testing data')
    thrember.download_dataset('datasets', file_type='Win64', split='test')
    print('finished')
else:
    print('downloading challenge data')
    thrember.download_dataset('datasets', file_type='Win64', split='challenge')
    print('finished')