import bcrypt
import uvicorn
import mysql.connector
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from starlette.middleware.cors import CORSMiddleware


class Token(BaseModel):
    access_token: str
    token_type: str
    expires: datetime


class TokenData(BaseModel):
    email: str or None = None


class Order(BaseModel):
    sharpening_company_id: int
    customer_id: int
    tool_id: int
    count: int


class Tool(BaseModel):
    name: str
    price: float or None = None
    discount: float or None = None
    note: str or None = None


class SharpeningCompany(BaseModel):
    name: str
    note: str or None = None


class Company(BaseModel):
    name: str
    state: str or None = None
    town: str or None = None
    street: str or None = None
    cislo_popisne: str or None = None
    psc: str or None = None
    phone: str or None = None
    email: str
    ic: str or None = None
    dic: str or None = None
    executive: str or None = None
    note: str or None = None


class User(BaseModel):
    username: str or None = None
    email: str
    disabled: bool = False


class UserRegistration(User):
    first_name: str
    last_name: str
    password: str
    phone: str or None = None
    company_id: int or None = None


class UserUpdate(UserRegistration):
    password: str or None = None


class UserInDB(User):
    password: str


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=['http://localhost:3000'],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def estabilish_connection(db_name):
    connection = mysql.connector.connect(host=host, user=user, password=psw, db=db_name)
    if connection.is_connected():
        return connection
    else:
        return False


def close_connection(connection):
    connection.disconnect()
    connection.close()


def insert_order(connection, sharpening_id, customer_id, tool_id, count):
    cursor = connection.cursor()

    insert_query = "INSERT INTO orders (sharpening_company, customer, tool, count) VALUES (%s, %s, %s, %s)"
    data_to_insert = (sharpening_id, customer_id, tool_id, count)
    cursor.execute(insert_query, data_to_insert)
    connection.commit()
    cursor.close()

    return True


def get_all_orders(connection):
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM orders')
    records = cursor.fetchall()
    cursor.close()

    result = []
    for record in records:
        result.append(
            {
                "id": record[0],
                "sharpening_id": record[1],
                "customer_id": record[2],
                "tool_id": record[3],
                "count": record[4]
            }
        )

    return result


def user_exists(cursor, email):
    select_query = "SELECT * FROM accounts WHERE email = %s"
    cursor.execute(select_query, (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        return existing_user

    return


def sharpening_company_exists(cursor, name):
    select_query = "SELECT * FROM sharpeningCompanies WHERE name = %s"
    cursor.execute(select_query, (name,))
    existing_company = cursor.fetchone()

    if existing_company:
        return existing_company

    return


def tool_exists(cursor, name):
    select_query = "SELECT * FROM tools WHERE name = %s"
    cursor.execute(select_query, (name,))
    existing_tool = cursor.fetchone()

    if existing_tool:
        return existing_tool

    return


def company_exists(cursor, name):
    select_query = "SELECT * FROM companies WHERE name = %s"
    cursor.execute(select_query, (name,))
    existing_company = cursor.fetchone()

    if existing_company:
        return existing_company

    return


def insert_sharpening_company(connection, name, note=None):
    cursor = connection.cursor()

    if not sharpening_company_exists(cursor, name):
        insert_query = "INSERT INTO sharpeningCompanies (name, note) VALUES (%s, %s)"
        data_to_insert = (name, note)
        cursor.execute(insert_query, data_to_insert)
        connection.commit()
        cursor.close()

        return True

    cursor.close()

    return False


def insert_company(connection, name, email, state=None, town=None, street=None, cislo_popisne=None, psc=None,
                   phone=None, ic=None, dic=None, executive=None, note=None):
    cursor = connection.cursor()

    if not company_exists(cursor, name):
        insert_query = ("INSERT INTO companies (name, state, town, street, cislo_popisne, psc, phone, email, ic, dic,"
                        "executive, note) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
        data_to_insert = (name, state, town, street, cislo_popisne, psc, phone, email, ic, dic, executive, note)
        cursor.execute(insert_query, data_to_insert)
        connection.commit()
        cursor.close()

        return True

    cursor.close()

    return False


def insert_tool(connection, name, price=None, discount=None, note=None):
    cursor = connection.cursor()

    if not tool_exists(cursor, name):
        insert_query = "INSERT INTO tools (name, price, discount, note) VALUES (%s, %s, %s, %s)"
        data_to_insert = (name, price, discount, note)
        cursor.execute(insert_query, data_to_insert)
        connection.commit()
        cursor.close()

        return True

    cursor.close()

    return False


def insert_account(connection, email, password, first_name, last_name, username=None, phone=None, disabled=False,
                   company_id=None):
    cursor = connection.cursor()

    if not user_exists(cursor, email):

        insert_query = ("INSERT INTO accounts (email, password, first_name, last_name, username, phone, disabled,"
                        "company_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)")
        data_to_insert = (email, hash_password(password), first_name, last_name, username, phone, disabled, company_id)
        cursor.execute(insert_query, data_to_insert)
        connection.commit()
        cursor.close()

        return True

    cursor.close()

    return False


def get_company_by_id(connection, identificator):
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM companies WHERE id = %s', (identificator, ))
    record = cursor.fetchone()
    cursor.close()

    if record:
        return {
            "id": record[0],
            "name": record[1],
            "state": record[2],
            "town": record[3],
            "street": record[4],
            "cislo_popisne": record[5],
            "psc": record[6],
            "phone": record[7],
            "email": record[8],
            "ic": record[9],
            "dic": record[10],
            "executive": record[11],
            "note": record[12]
        }

    return None


def get_all_sharpening_companies(connection):
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM sharpeningCompanies')
    records = cursor.fetchall()
    cursor.close()

    result = []
    for record in records:
        result.append(
            {
                "id": record[0],
                "name": record[1],
                "note": record[2]
            }
        )

    return result


def edit_sharpening_comp(connection, identificator, name, note=None):
    cursor = connection.cursor()

    sql_query = """
               UPDATE sharpeningCompanies
               SET name = %s, note = %s
               WHERE id = %s
           """

    cursor.execute(sql_query, (name, note, identificator))

    connection.commit()
    cursor.close()

    return


def edit_comp(connection, identificator, name, state=None, town=None, street=None, cislo_popisne=None, psc=None,
              phone=None, email=None, ic=None, dic=None, executive=None, note=None):
    cursor = connection.cursor()

    sql_query = """
               UPDATE companies
               SET name = %s, town = %s, street = %s, state = %s, cislo_popisne = %s, psc = %s, phone = %s, email = %s,
               ic = %s, dic = %s, executive = %s, note = %s
               WHERE id = %s
           """

    cursor.execute(sql_query, (name, town, street, state, cislo_popisne, psc, phone, email, ic, dic, executive,
                               note, identificator))

    connection.commit()
    cursor.close()

    return


def get_all_companies(connection):
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM companies')
    records = cursor.fetchall()
    cursor.close()

    result = []
    for record in records:
        result.append(
            {
                "id": record[0],
                "name": record[1],
                "state": record[2],
                "town": record[3],
                "street": record[4],
                "cislo_popisne": record[5],
                "psc": record[6],
                "phone": record[7],
                "email": record[8],
                "ic": record[9],
                "dic": record[10],
                "executive": record[11],
                "note": record[12]
            }
        )

    return result


def get_all_tools(connection):
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM tools')
    records = cursor.fetchall()
    cursor.close()

    result = []
    for record in records:
        result.append(
            {
                "id": record[0],
                "name": record[1],
                "price": record[2],
                "discount": record[3],
                "note": record[4],
            }
        )

    return result


def get_all_accounts(connection):
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM accounts')
    records = cursor.fetchall()
    cursor.close()

    result = []
    for record in records:
        result.append(
            {
                "id": record[0],
                "username": record[1],
                "email": record[5],
                "first_name": record[3],
                "last_name": record[4],
                "phone": record[6],
                "linked_company": get_company_by_id(connection, record[7]),
             }
        )

    return result


def delete_account(connection, identificator):
    cursor = connection.cursor()
    cursor.execute(f'DELETE FROM accounts WHERE id = {identificator}')
    connection.commit()
    cursor.close()

    return


def delete_sharpening_comp(connection, identificator):
    cursor = connection.cursor()
    cursor.execute(f'DELETE FROM sharpeningCompanies WHERE id = {identificator}')
    connection.commit()
    cursor.close()

    return


def delete_sharpening_comps(ids):
    connection = estabilish_connection(database)

    for identificator in ids:
        delete_sharpening_comp(connection, identificator)

    close_connection(connection)

    return


def delete_comp(connection, identificator):
    cursor = connection.cursor()
    cursor.execute(f'DELETE FROM companies WHERE id = {identificator}')
    connection.commit()
    cursor.close()

    return


def delete_comps(ids):
    connection = estabilish_connection(database)

    for identificator in ids:
        delete_comp(connection, identificator)

    close_connection(connection)

    return


def del_tool(connection, identificator):
    cursor = connection.cursor()
    cursor.execute(f'DELETE FROM tools WHERE id = {identificator}')
    connection.commit()
    cursor.close()

    return


def del_tools(ids):
    connection = estabilish_connection(database)

    for identificator in ids:
        del_tool(connection, identificator)

    close_connection(connection)

    return


def edit_tool(connection, identificator, name, price=None, discount=None, note=None):
    cursor = connection.cursor()

    sql_query = """
               UPDATE tools
               SET name = %s, price = %s, discount = %s, note = %s
               WHERE id = %s
           """

    cursor.execute(sql_query, (name, price, discount, note, identificator))

    connection.commit()
    cursor.close()

    return


def delete_accounts(ids):
    connection = estabilish_connection(database)

    for identificator in ids:
        delete_account(connection, identificator)

    close_connection(connection)

    return


def edit_account(connection, identificator, email, first_name, last_name, username=None, phone=None, password=None,
                 company_id=None):

    cursor = connection.cursor()
    if password is None or password == '':
        sql_query = """
                UPDATE accounts
                SET username = %s, email = %s, first_name = %s, last_name = %s, phone = %s, company_id = %s
                WHERE id = %s
            """

        cursor.execute(sql_query, (username, email, first_name, last_name, phone, company_id, identificator))

    else:
        sql_query = """
                UPDATE accounts
                SET username = %s, email = %s, first_name = %s, last_name = %s, phone = %s, company_id = %s,
                password = %s
                WHERE id = %s
            """

        cursor.execute(sql_query, (username, email, first_name, last_name, phone, hash_password(password), company_id,
                                   identificator))

    connection.commit()
    cursor.close()

    return


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    return hashed_password.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


def get_user(db, email: str):
    connection = estabilish_connection(db)
    cursor = connection.cursor()
    acc = user_exists(cursor, email)

    cursor.close()
    close_connection(connection)

    if acc:
        return UserInDB(email=acc[5], password=acc[2], disabled=acc[8])

    return


def authenticate_user(db, email: str, password: str):
    user_db = get_user(db, email)

    if not user_db:
        return False

    if not verify_password(password, user_db.password):
        return False

    if user_db.disabled:
        return 'disabled'

    return user_db


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=8)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                         detail="Could not validate credentials",
                                         headers={"WWW-Authenticate": "Bearer"})

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")

        if email is None:
            raise credential_exception

        token_data = TokenData(email=email)

    except JWTError:
        raise credential_exception

    user_db = get_user(database, email=token_data.email)

    if user_db is None:
        raise credential_exception

    return user_db


async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):

    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Account is not activated")

    return current_user


@app.post('/createSharpeningCompany')
async def createSharpeningCompany(company: SharpeningCompany, current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection('aparatea_fig')

    if not connection:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Connecting to db failed...")

    if company.note == '':
        company.note = None

    company_inserted = insert_sharpening_company(connection, name=company.name, note=company.note)

    close_connection(connection)

    if not company_inserted:
        return 'Sharpening company already exists!'

    return 'Sharpening company added successfully'


@app.post('/register')
async def register(usr: UserRegistration, current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection('aparatea_fig')

    if not connection:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Connecting to db failed...")

    if usr.phone == '':
        usr.phone = None
    if usr.username == '':
        usr.phone = None
    if usr.company_id == 0:
        usr.company_id = None

    account_inserted = insert_account(connection, email=usr.email, password=usr.password, first_name=usr.first_name,
                                      last_name=usr.last_name, username=usr.username, phone=usr.phone,
                                      company_id=usr.company_id)
    close_connection(connection)
    if not account_inserted:
        return 'User already exists!'

    return 'Registered successfully'


@app.post('/login', response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user_authenticated = authenticate_user(database, form_data.username, form_data.password)

    if user_authenticated == 'disabled':
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Account not active")

    if not user_authenticated:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect credentials",
                            headers={"WWW-Authenticate": "Bearer"})

    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(data={"sub": user_authenticated.email}, expires_delta=access_token_expires)

    return {"access_token": access_token, "token_type": "bearer", "expires": access_token_expires+datetime.utcnow()}


@app.get("/sharpeningCompanies")
async def get_sharpening_companies(current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection(database)
    result = get_all_sharpening_companies(connection)
    close_connection(connection)

    return result


@app.delete("/deleteSharpeningCompany")
async def delete_sharpening_company(identificator: int, current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection(database)
    delete_sharpening_comp(connection, identificator)
    close_connection(connection)

    return


@app.delete("/deleteSharpeningCompanies")
async def delete_sharpening_companies(ids: list[int], current_user: User = Depends(get_current_active_user)):
    delete_sharpening_comps(ids)

    return


@app.post("/editSharpeningCompany")
async def edit_sharpening_company(identificator: int, sharpening_company: SharpeningCompany,
                                  current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection(database)
    if sharpening_company.note == '':
        sharpening_company.note = None

    if sharpening_company.name == '' or sharpening_company.name is None:
        close_connection(connection)
        return HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT,
                             detail="Some fields that are meant to be filled are empty!")

    cursor = connection.cursor()
    company = sharpening_company_exists(cursor, sharpening_company.name)

    if company and company[0] != identificator:
        cursor.close()
        close_connection(connection)
        return HTTPException(status_code=status.HTTP_304_NOT_MODIFIED,
                             detail="Sharpening company with this name already exists")

    cursor.close()

    edit_sharpening_comp(connection, identificator=identificator, name=sharpening_company.name,
                         note=sharpening_company.note)

    close_connection(connection)

    return


@app.delete("/deleteCompany")
async def delete_company(identificator: int, current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection(database)
    delete_comp(connection, identificator)
    close_connection(connection)

    return


@app.delete("/deleteCompanies")
async def delete_companies(ids: list[int], current_user: User = Depends(get_current_active_user)):
    delete_comps(ids)

    return


@app.get("/companies")
async def get_companies(current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection(database)
    result = get_all_companies(connection)
    close_connection(connection)

    return result


@app.post("/createCompany")
async def create_company(company: Company, current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection(database)

    if not connection:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Connecting to db failed...")

    for attribute in company:
        if attribute[1] == '':
            setattr(company, attribute[0], None)

    if company.email is None or company.name is None:
        close_connection(connection)
        return HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT,
                             detail="Some fields that are meant to be filled are empty!")

    company_inserted = insert_company(connection, name=company.name, email=company.email, state=company.state,
                                      town=company.town, street=company.street, cislo_popisne=company.cislo_popisne,
                                      psc=company.psc, phone=company.phone, ic=company.ic, dic=company.dic,
                                      executive=company.executive, note=company.note)
    close_connection(connection)

    if not company_inserted:
        return 'Company already exists!'

    return 'Company added successfully'


@app.post("/editCompany")
async def edit_company(identificator: int, company: Company, current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection(database)

    for attribute in company:
        if attribute[1] == '':
            setattr(company, attribute[0], None)

    if company.email is None or company.name is None:
        close_connection(connection)
        return HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT,
                             detail="Some fields that are meant to be filled are empty!")

    cursor = connection.cursor()
    company_existing = company_exists(cursor, company.email)

    if company_existing and company_existing[0] != identificator:
        cursor.close()
        close_connection(connection)
        return HTTPException(status_code=status.HTTP_304_NOT_MODIFIED, detail="Company with this name already exists")

    cursor.close()

    edit_comp(connection, identificator=identificator, name=company.name, state=company.state, town=company.town,
              street=company.street, cislo_popisne=company.cislo_popisne, psc=company.psc, phone=company.phone,
              email=company.email, ic=company.ic, dic=company.dic, executive=company.executive, note=company.note)

    close_connection(connection)

    return


@app.get("/users")
async def get_users(current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection(database)
    result = get_all_accounts(connection)
    close_connection(connection)

    return result


@app.delete("/deleteUser")
async def delete_user_account(identificator: int, current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection(database)
    delete_account(connection, identificator)
    close_connection(connection)

    return


@app.delete("/deleteUsers")
async def delete_users_accounts(ids: list[int], current_user: User = Depends(get_current_active_user)):
    delete_accounts(ids)

    return


@app.post("/editUser")
async def edit_user_account(identificator: int, usr: UserUpdate, current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection(database)
    if usr.phone == '':
        usr.phone = None
    if usr.username == '':
        usr.username = None
    if usr.company_id == 0:
        usr.company_id = None
    if usr.email == '' or usr.first_name == '' or usr.last_name == '':
        close_connection(connection)
        return HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT,
                             detail="Some fields that are meant to be filled are empty!")

    cursor = connection.cursor()
    user_w_email = user_exists(cursor, usr.email)

    if user_w_email and user_w_email[0] != identificator:
        cursor.close()
        close_connection(connection)
        return HTTPException(status_code=status.HTTP_304_NOT_MODIFIED, detail="Account with this email already exists!")

    cursor.close()

    edit_account(connection, identificator=identificator, email=usr.email, first_name=usr.first_name,
                 last_name=usr.last_name, username=usr.username, phone=usr.phone, password=usr.password,
                 company_id=usr.company_id)

    close_connection(connection)

    return


@app.post("/createTool")
async def create_tool(tool: Tool, current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection(database)

    if not connection:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Connecting to db failed...")

    for attribute in tool:
        if attribute[1] == '':
            setattr(tool, attribute[0], None)

    if tool.discount == -1:
        tool.discount = None
    if tool.price == -1:
        tool.price = None

    if tool.name is None or (tool.price is None and tool.discount is not None):
        close_connection(connection)
        return HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT,
                             detail="Some fields that are meant to be filled are empty!")

    tool_inserted = insert_tool(connection, name=tool.name, price=tool.price, discount=tool.discount, note=tool.note)
    close_connection(connection)

    if not tool_inserted:
        return 'Tool already exists!'

    return 'Tool added successfully'


@app.get("/tools")
async def get_tools(current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection(database)
    result = get_all_tools(connection)
    close_connection(connection)

    return result


@app.delete("/deleteTool")
async def delete_tool(identificator: int, current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection(database)
    del_tool(connection, identificator)
    close_connection(connection)

    return


@app.delete("/deleteTools")
async def delete_tools(ids: list[int], current_user: User = Depends(get_current_active_user)):
    del_tools(ids)

    return


@app.post("/editTool")
async def edit_given_tool(identificator: int, tool: Tool, current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection(database)

    if tool.note == '':
        tool.note = None

    if tool.price == -1:
        tool.price = None
        tool.discount = None

    if tool.discount == -1:
        tool.discount = None

    if tool.name == '' or (tool.price is None and tool.discount is not None):
        close_connection(connection)
        return HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT,
                             detail="Some fields that are meant to be filled are empty!")

    cursor = connection.cursor()
    tool_db = tool_exists(cursor, tool.name)

    if tool_db and tool_db[0] != identificator:
        cursor.close()
        close_connection(connection)
        return HTTPException(status_code=status.HTTP_304_NOT_MODIFIED,
                             detail="Tool with this name already exists")

    cursor.close()

    edit_tool(connection, identificator=identificator, name=tool.name, price=tool.price, discount=tool.discount,
              note=tool.note)

    close_connection(connection)

    return


@app.post("/createOrder")
async def create_order(order: Order, current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection(database)

    if not connection:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Connecting to db failed...")

    insert_order(connection=connection, sharpening_id=order.sharpening_company_id, customer_id=order.customer_id,
                 tool_id=order.tool_id, count=order.count)

    close_connection(connection)

    return status.HTTP_201_CREATED


@app.get("/orders")
async def get_orders(current_user: User = Depends(get_current_active_user)):
    connection = estabilish_connection(database)
    result = get_all_orders(connection)
    close_connection(connection)

    return result


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=3001, reload=True)
