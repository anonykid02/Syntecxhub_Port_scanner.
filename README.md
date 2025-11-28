# Run command
chmod +x port_scanner.py

# Requirements (install before running)
pip install colorama tqdm

#if error comes as - "externally-managed-environment" then try.. 
pip install colorama tqdm --break-system-packages

./port_scanner.py

# OR
python3 port_scanner.py
