rm -rf USSCS
git clone https://github.com/tchello45/USSCS.git
cd USSCS/usscs
python3 setup.py install
cd ..
cd usscs_enc
python3 setup.py install
cd ..
cd ..
rm -rf USSCS