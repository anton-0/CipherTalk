# CipherTalk

CipherTalk is a secure communication tool developed during 3rd year of Computer Science course at Gdańsk University of Technology.

---

## Configuration
Create a virtual environment and install packages from requirements.txt.

Before you start the app, you must generate yourself a pair of RSA keys, as well as a local key. The local key will be used to encrypt your private key. So whenever you start the app, you have to enter the password.

To generate keys run:
```
cd libs
python key_generation.py {your_password}
```

## Usage

To start the app simply run `main.py` providing such arguments as:
    username, host address, destination address and destination port. Example:

```
python main.py IronMan 40001 192.168.10.10 40001
```
