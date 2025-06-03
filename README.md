# Apaches - HackMyVM (Easy)

![Apaches.png](Apaches.png)

## Übersicht

*   **VM:** Apaches
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Apaches)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 30. Mai 2025
*   **Original-Writeup:** https://alientec1908.github.io/Apaches_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Die Challenge "Apaches" ist eine als "Easy" eingestufte virtuelle Maschine von der Plattform HackMyVM. Ziel ist es, initialen Zugriff auf das System zu erlangen und anschließend Root-Rechte zu erhalten. Der Lösungsweg beinhaltet die Ausnutzung der bekannten Apache-Schwachstelle CVE-2021-41773 (Path Traversal & RCE) für den initialen Zugriff als `daemon`-Benutzer. Die weitere Privilegienerweiterung erfolgt durch das Ausnutzen einer weltlesbaren `/etc/shadow`-Datei zum Knacken eines Benutzerpassworts, die Modifikation eines von einem anderen Benutzer über eine Gruppenmitgliedschaft schreibbaren Cron-Skripts und schließlich die Ausnutzung einer unsicheren `sudo`-Regel, die `nano` als einen anderen Benutzer erlaubt.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   Texteditor (z.B. `vi`, `nano`)
*   `nmap`
*   `curl`
*   `nikto`
*   `gobuster` / `feroxbuster`
*   Base64 Decode Tools
*   `ssh`
*   `hydra`
*   `searchsploit`
*   `nc` (netcat)
*   `find`
*   `python3 http.server`
*   `unshadow`
*   `john` (John the Ripper)
*   `sudo`
*   `su`
*   Standard Linux-Befehle (`ls`, `cat`, `cp`, `echo`, `grep`, `stty`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Apaches" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   Identifizierung der Ziel-IP (`192.168.2.207`) mittels `arp-scan`.
    *   Portscan mit `nmap` offenbarte offene Ports 22 (SSH - OpenSSH 8.2p1 Ubuntu) und 80 (HTTP - Apache 2.4.49).
    *   Hinzufügen von `apaches.hmv` zur lokalen `/etc/hosts`-Datei.
    *   Web-Enumeration mit `nikto` und `gobuster` zeigten Directory Indexing, eine veraltete Apache-Version und einen Base64-kodierten Hinweis in `robots.txt` auf "Pocahontas". Im Verzeichnis `/images/team/` wurden die Namen `geronimo`, `pocahontas`, `sacagawea`, `squanto` gefunden.

2.  **Initial Access (Apache RCE CVE-2021-41773):**
    *   Die Apache-Version 2.4.49 ist anfällig für Path Traversal und RCE (CVE-2021-41773).
    *   Ein öffentliches Exploit-Skript (`50383.sh` von Exploit-DB) wurde verwendet, um RCE zu erlangen und Befehle als Benutzer `daemon` auszuführen.
    *   Eine Reverse Shell wurde mittels `nc` als `daemon`-Benutzer etabliert.

3.  **Privilege Escalation (von `daemon` zu `squanto`):**
    *   Als `daemon` wurde festgestellt, dass die Datei `/etc/shadow` weltlesbar ist.
    *   Die Inhalte von `/etc/passwd` und `/etc/shadow` wurden kopiert.
    *   Mittels `unshadow` und `john` (mit `rockyou.txt`) wurde das Passwort `iamtheone` für den Benutzer `squanto` geknackt.
    *   Erfolgreicher SSH-Login als `squanto` mit dem gefundenen Passwort. Die User-Flag "Well done!" (ASCII-Art) wurde in `/home/squanto/user.txt` gefunden.

4.  **Privilege Escalation (von `squanto` zu `sacagawea`):**
    *   Als `squanto` wurde ein auskommentierter Cronjob für `sacagawea` gefunden, der auf das Skript `/home/sacagawea/Scripts/backup.sh` verwies.
    *   Der Benutzer `squanto` war Mitglied der Gruppe `Lipan`, welche Schreibrechte auf `backup.sh` hatte.
    *   Das `backup.sh`-Skript wurde modifiziert, um eine Reverse Shell zum Angreifer-System aufzubauen.
    *   Nach kurzer Wartezeit (vermutlich Ausführung des modifizierten Skripts durch einen Mechanismus als `sacagawea`) wurde eine Shell als `sacagawea` erlangt. Die User-Flag "FlagsNeverQuitNeitherShouldYou" (ASCII-Art) wurde in `/home/sacagawea/user.txt` gefunden.

5.  **Privilege Escalation (von `sacagawea` zu `geronimo` und dann zu `root`):**
    *   Im Verzeichnis `/home/sacagawea/Development/admin/` wurde die Datei `2-check.php` gefunden, die Klartext-Passwörter für `geronimo`, `pocahontas`, `squanto` und `sacagawea` enthielt.
    *   Wechsel zum Benutzer `pocahontas` mit `su pocahontas` und dem Passwort `y2U1@8Ie&OHwd^Ww3uAl`.
    *   `sudo -l` als `pocahontas` zeigte, dass `/bin/nano` als Benutzer `geronimo` ausgeführt werden konnte.
    *   Ausnutzung dieser `sudo`-Regel (GTFOBins `nano` Sudo Exploit), um eine Shell als `geronimo` zu erlangen.
    *   `sudo -l` als `geronimo` offenbarte `(ALL) NOPASSWD: ALL`.
    *   Mittels `sudo su` wurde eine Root-Shell erlangt.

## Wichtige Schwachstellen und Konzepte

*   **Veraltete Software / Bekannte Schwachstelle:** Apache 2.4.49 war anfällig für CVE-2021-41773 (Path Traversal & RCE).
*   **Unsichere Dateiberechtigungen:** Die Datei `/etc/shadow` war weltlesbar, was das Offline-Cracking von Benutzerpasswörtern ermöglichte.
*   **Unsichere Gruppenberechtigungen / Schreibbares Skript:** Der Benutzer `squanto` konnte über eine Gruppenmitgliedschaft (`Lipan`) ein Skript modifizieren, das von einem anderen Benutzer (`sacagawea`) ausgeführt wurde.
*   **Klartext-Passwörter im Quellcode:** Die Datei `2-check.php` enthielt hartkodierte Passwörter für mehrere Benutzer.
*   **Unsichere sudo-Regel:** Die Erlaubnis für `pocahontas`, `nano` als `geronimo` auszuführen, ermöglichte eine Eskalation zum Benutzer `geronimo`.
*   **Überprivilegierte sudo-Rechte:** Der Benutzer `geronimo` hatte `(ALL) NOPASSWD: ALL` in der `sudoers`-Datei, was eine direkte Eskalation zu `root` ermöglichte.

## Flags

*   **User Flag (`squanto` - `/home/squanto/user.txt`):** `Well done!` (als Teil von ASCII-Art)
*   **User Flag (`sacagawea` - `/home/sacagawea/user.txt`):** `FlagsNeverQuitNeitherShouldYou` (als Teil von ASCII-Art)
*   **Root Flag (Pfad nicht explizit im Log, aber als `root` erlangt):** `OneSingleVulnerabilityAllAnAttackerNeeds`

## Tags

`HackMyVM`, `Apaches`, `Easy`, `CVE-2021-41773`, `Apache RCE`, `Password Cracking`, `/etc/shadow`, `SUID/SGID`, `Cronjob Exploit`, `Sudo Exploit`, `Nano Exploit`, `Linux`, `Web`, `Privilege Escalation`
