import json
from datetime import datetime

import psycopg2

from utils import hash_file, tag_results


# Connect to PostgreSQL
def initalizeDatabase():
    try:
        connection = psycopg2.connect(
            user="postgres",
            password="fukhara",
            host="localhost",
            port=5432,
            database="fukhara",
        )

        cursor = connection.cursor()

        create_apk_analysis_table_query = """
        CREATE TABLE IF NOT EXISTS apk_analysis (
                ID INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY NOT NULL,
                SHA256 VARCHAR(64) UNIQUE NOT NULL,
                UPLOADED_AT TIMESTAMP NOT NULL,
                APK_FILENAME VARCHAR(255) NULL,
                ANALYSIS_RESULTS JSONB[]);
        """
        cursor.execute(create_apk_analysis_table_query)
        connection.commit()
        print("apk_analysis table created!")

        create_fuzzy_hash_table_query = """
        CREATE TABLE IF NOT EXISTS fuzzy_hash (
                ID INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY NOT NULL,
                FILENAME VARCHAR(255) NOT NULL,
                HASH VARCHAR UNIQUE NOT NULL,
                APK_ID INT NOT NULL,
                FOREIGN KEY (APK_ID) REFERENCES apk_analysis(ID));
        """
        cursor.execute(create_fuzzy_hash_table_query)
        connection.commit()
        print("fuzzy_hash table created!")
    except Exception as e:
        print("Failed to initialize database!")
        print(e)


def add_apk_analysis(path):
    try:
        connection = psycopg2.connect(
            user="postgres",
            password="fukhara",
            host="localhost",
            port=5432,
            database="fukhara",
        )

        cursor = connection.cursor()

        sha256 = hash_file(path)
        uploaded_at = str(datetime.now())

        insert_query = f"""
        INSERT INTO apk_analysis (SHA256, UPLOADED_AT)
        VALUES ('{sha256}', '{uploaded_at}')
        ON CONFLICT (SHA256) DO NOTHING
        """
        cursor.execute(insert_query)
        connection.commit()

    except Exception as e:
        print("Failed to add apk analysis!")
        print(e)


def add_ssdeep_hash(apk_id, filename, ssdeep_hash):
    try:
        connection = psycopg2.connect(
            user="postgres",
            password="fukhara",
            host="localhost",
            port=5432,
            database="fukhara",
        )

        cursor = connection.cursor()

        insert_query = f"""
        INSERT INTO fuzzy_hash (FILENAME, HASH, APK_ID)
        VALUES ('{filename}', '{ssdeep_hash}', '{apk_id}')
        ON CONFLICT (HASH) DO NOTHING
        """
        cursor.execute(insert_query)
        connection.commit()

    except Exception as e:
        print("Failed to add ssdeep hash!")
        print(e)


def add_tool_analysis(file_hash, tool, results):
    try:
        connection = psycopg2.connect(
            user="postgres",
            password="fukhara",
            host="localhost",
            port=5432,
            database="fukhara",
        )

        cursor = connection.cursor()

        tagged_results = tag_results(tool, results)

        update_query = f"""
        UPDATE apk_analysis
        SET ANALYSIS_RESULTS = ANALYSIS_RESULTS || %s::jsonb
        WHERE sha256 = '{file_hash}'
        """
        cursor.execute(update_query, (json.dumps(tagged_results),))
        connection.commit()

    except Exception as e:
        print(f"Failed to add {tool}!")
        print(e)


def get_apk_id(file_hash):
    try:
        connection = psycopg2.connect(
            user="postgres",
            password="fukhara",
            host="localhost",
            port=5432,
            database="fukhara",
        )

        cursor = connection.cursor()

        select_query = f"""
        SELECT (ID) FROM apk_analysis
        WHERE SHA256 = '{file_hash}'
        """
        cursor.execute(select_query)
        connection.commit()

        apk_id = cursor.fetchone()[0]
        return apk_id

    except Exception as e:
        print(f"Failed to get apk ID!")
        print(e)
