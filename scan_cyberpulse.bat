@echo off
echo ========================================
echo    CYBER PULSE - Script d'audit reseau
echo    Date : %date% %time%
echo ========================================

echo [1/4] Scan des ports ouverts
nmap scanme.nmap.org -oN resultats\01_ports.txt

echo [2/4] Detection des versions de services
nmap -sV scanme.nmap.org -oN resultats\02_versions.txt

echo [3/4] Analyse des en-tetes HTTP
nmap -sV --script=http-headers scanme.nmap.org -oN resultats\03_http.txt

echo [4/4] Verification certificat SSL
nmap --script=ssl-cert scanme.nmap.org -oN resultats\04_ssl.txt

echo ========================================
echo    Rapport complet genere dans /resultats
echo ========================================
pause