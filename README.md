# What is ddmail_openpgp_keyhandler
Web application API to handle OpenPGP keys and keyrings for the ddmail project.

## What is ddmail
DDMail is a e-mail system/service and e-mail provider with strong focus on security, privacy and anonymity. A current production example can be found at www.ddmail.se

## Operating system
Developt for and tested on debian 12.

## Building and installing from source using hatchling.
Step 1: clone github repo<br>
`git clone https://github.com/drzobin/ddmail_openpgp_keyhandler [code path]`<br>
`cd [code path]`<br>
<br>
Step 2: Setup python virtual environments<br>
`python -m venv [venv path]`<br>
`source [venv path]/bin/activate`<br>
<br>
Step 3: Install package and required dependencies<br>
`pip install -e .[dev]`<br>
<br>
Step 4: Build package<br>
`python -m pip install --upgrade build`<br>
`python -m build `<br><br>
Packages is now located under dist folder<br>
<br>
Step 5: Install package<br>
`pip install dist/[package name].whl`

## Testing
`cd [code path]`<br>
`pytest --cov=ddmail_openpgp_keyhandler tests/ --config=[config file path]`

## Coding
Follow PEP8 and PEP257. Use Flake8 with flake8-docstrings for linting. Strive for 100% test coverage.
