# Auth
How to setup the project on your local machine
1. create a parent directory i.e "food"
2. clone the repository
3. open terminal at the project root
4. create virtual environment using "python -m venv venv"
5. Activate environment 

    Windows: venv\Scripts\activate
    MacOs/Linux: source venv/bin/activate

6. Install packages

    pip install -r requirements.txt

7. create environment variables ".env" in project root
8. Set your environment Variables as shown by .env.examples file
9. Install Rabbitmq 
10. Migrate migrations by:
    python manage.py migrate
10. Runserver by:
    python manage.py runserver
11. Access app via:
    http://localhost:8000
