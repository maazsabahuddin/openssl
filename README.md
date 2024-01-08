This script is being written in Python programming language, and the primary purpose of this script is to fetch the overall network and discover the expiring certificates, then make a report based on the expiring certs, and share the report to the respective email.

Prerequisites:

- Python version should be > 3.8
- Git should be installed

HOW TO RUN OR EXECUTE THE SCRIPT

1) Clone the project using the following command: `git clone https://github.com/maazsabahuddin/openssl.git`.
2) Enter your username and password, and please make sure you have access to this repository.
3) After successfully cloning the project, you have to create a virtual environment by typing the following command `python -m venv venv`.
4) Activate the virtual environment by typing `venv/Scripts/activate` in Windows, and `venv/bin/activate` in Linux.
5) Once the venv is activated, please install the required packages to run the script by typing `pip install -r requirments.txt`.
6) Create a .env file locally and add the KEY VALUE pairs. Please refer to the Sharepoint IT-Department group then move to `Documents > In site library > Sharepoint Project > Certificate Expiry Discovery > .env`.
7) After successfully setting up .env file. Please run the `main.py` file by moving to the `certificate-expiry-reminder` directory and run the following command `python main.py`.
8) The script will send a report to the mentioned email address in .env file.
9) Enjoy.

Please feel free to reach out to `maazsabahuddin@gmail.com` if you face any issue or required any sort of help.
