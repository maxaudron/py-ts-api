# py-ts-api  
## A REST API for TeamSpeak Serverquery written in Python  
  
### Installation  
#### Dependencies
* Python 3+ (i recommend 3.6.2)
* pyenv (optional)
* PiP
  * flask
  * flask_httpauth
  * itsdangerous
  * ts3 (py-ts3)
  
#### Installation
I recommend using a virtual python enviroment and will be using pyenv-virtualenv in this explanation  
Clone the repo and switch to it  
    `git clone https://gitlab.com/audron/py-ts-api.git`  
    `cd py-ts-api`  
Install python version and create virtualenv  
    `pyenv install 3.6.2`  
    `pyenv virtualenv 3.6.2 py-ts-api` 
Set local python version to our virtualenv  
    `pyenv local py-ts-api`  
Install dependencies  
    `pip install flask flask_httpauth itsdangerous ts3`  
  
You are now ready to run the API in a development enviroment with `./app.py` if you are only using it in private this may be ok but for heavier usage i highly recommend deploying it to a preduction enviroment.
For more details on that refer to the [Flask documentation](http://flask.pocoo.org/docs/0.12/deploying/#deployment)