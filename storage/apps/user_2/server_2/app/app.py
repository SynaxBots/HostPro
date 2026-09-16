import time
print('Starting memory test...', flush=True)
chunks = []
for i in range(40):
    chunks.append(b'x' * (10 * 1024 * 1024))
    print(f'Allocated {(i+1)*10} MB', flush=True)
    time.sleep(0.3)
print('⚠️ Reached the target allocation without being stopped.', flush=True)
time.sleep(10)
