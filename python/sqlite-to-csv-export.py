import sqlite3
import csv
import sys

def sqlite_to_csv(db_file, table_name, csv_file):
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Get the data from the table
        cursor.execute(f"SELECT * FROM {table_name}")
        data = cursor.fetchall()

        # Get the column names
        column_names = [description[0] for description in cursor.description]

        # Write the data to a CSV file
        with open(csv_file, 'w', newline='', encoding='utf-8') as csv_file:
            csv_writer = csv.writer(csv_file)
            
            # Write the header
            csv_writer.writerow(column_names)
            
            # Write the data
            csv_writer.writerows(data)

        print(f"Data from table '{table_name}' has been exported to '{csv_file}' successfully.")

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python script.py <database_file> <table_name> <csv_file>")
        sys.exit(1)

    db_file = sys.argv[1]
    table_name = sys.argv[2]
    csv_file = sys.argv[3]

    sqlite_to_csv(db_file, table_name, csv_file)
