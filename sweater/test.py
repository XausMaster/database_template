import sqlite3

comm = sqlite3.connect(r'C:\Users\User\Desktop\Tapsiriq\instance\data.db')
c = comm.cursor()
c.execute('ALTER TABLE user MODIFY question VARCHAR(50) NOT NULL')
c.commit()
# c.execute('SELECT * FROM user')
# data = c.fetchall()
comm.close()