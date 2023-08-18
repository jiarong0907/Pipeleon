sudo apt-get update
sudo apt-get install -y git python3.9
# set default python3 version to 3.9
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 1
sudo apt-get install -y python3-distutils
# install pip
wget https://bootstrap.pypa.io/get-pip.py
sudo python3.9 get-pip.py


git clone https://github.com/jiarong0907/Pipeleon.git
cd Pipeleon
# install python3 requirements
pip install -r requirements.txt
# install pytest (pytest-3)
sudo apt-get install -y python3-pytest
pytest-3 --workers auto
