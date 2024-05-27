from fastapi import FastAPI, Depends, HTTPException
from jose import jwt, JWTError
from datetime import datetime,timedelta
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from typing import Annotated


from typing import Annotated

ALGORITHM : str = "HS256"
SECRET_KEY : str = "A very Secure Secret Key"

def create_access_token(subject: str , expires_delta: timedelta) -> str:

    expire = datetime.utcnow() + expires_delta

    to_encode = {"exp": expire, "sub": str(subject)}

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm= ALGORITHM)
    
    return encoded_jwt

def decode_access_token(access_token:str):
    decoded_data=jwt.decode( access_token, SECRET_KEY, algorithms= [ALGORITHM] )
    return decoded_data


app=FastAPI()

#fake users data

fake_users_db: dict[str, dict[str, str]] = {
    "ameenalam": {
        "username": "ameenalam",
        "full_name": "Ameen Alam",
        "email": "ameenalam@example.com",
        "password": "ameenalamsecret",
    },
    "mjunaid": {
        "username": "mjunaid",
        "full_name": "Muhammad Junaid",
        "email": "mjunaid@example.com",
        "password": "mjunaidsecret",
    },
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login-endpoint")

@app.post("/login-endpoint")
def login_request(data_from_user:Annotated[OAuth2PasswordRequestForm,Depends(OAuth2PasswordRequestForm)]):
    #step 1 username exist in Database - Else Error
    user_in_fake_db = fake_users_db.get(data_from_user.username)
    if user_in_fake_db is None:
        raise HTTPException(status_code=400, detail="Incorrect username")
        #step 2 Check Passwrod Error
    if user_in_fake_db["password"] != data_from_user.password:
        raise HTTPException(status_code=400, detail="Incorrect Password")

    #Step 3 Generate Token
     
    access_token_expiry_minutes= timedelta(minutes=1)
    generated_token= create_access_token(subject=data_from_user.username, expires_delta=access_token_expiry_minutes)
    return{"username": data_from_user.username,"access_token": generated_token}

@app.get("/all_users")
def get_all_users(token: Annotated[str,Depends(oauth2_scheme)]):
    return fake_users_db

@app.get("/special-items")
def get_special_items(token: Annotated[str, Depends(oauth2_scheme)]):
    #DECODE data
    decoded_data=jwt.decode(token, SECRET_KEY, algorithms= [ALGORITHM] )

    return{"special":"items","decoded_data":decoded_data}

@app.get("/")
def read_root():
    return {"message": "Welcome to this fantastic app!"}

@app.get("/get-token")
def get_token(name:str):
    access_token_expiry_minutes= timedelta(minutes=1)
    
    print("access_token_expiry_minutes", access_token_expiry_minutes)

    generated_token= create_access_token(subject=name, expires_delta=access_token_expiry_minutes)
    return{"access_token":generated_token}


@app.get("/decode_token")
def decode_token(token:str):
    try:
        decoded_data=decode_access_token(token)
        return {"decoded_data":decoded_data}
    except JWTError as e:
        return {"error":str(e)}
    
    