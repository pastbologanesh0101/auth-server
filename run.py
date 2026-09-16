"""Dev entrypoint: ``python run.py`` starts the Flask dev server."""

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
