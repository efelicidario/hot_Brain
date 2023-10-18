from app import app, db

def create_and_commit_database():
        app.app_context().push()
        db.create_all()
        db.session.commit()


if __name__ == "__main__":
    create_and_commit_database()
    exit()