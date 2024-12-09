import random
import string

def generate_random_string(length):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(length))

data_length = 2048

with open("test.txt", "w") as f:
    f.write(generate_random_string(data_length))

print("Generate Data Done")