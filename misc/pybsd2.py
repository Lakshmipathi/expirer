from bsddb import db

filename = 'my_db.db'
fruitDB = db.DB()
fruitDB.open(filename, None, db.DB_BTREE, db.DB_DIRTY_READ)
cursor = fruitDB.cursor()
rec = cursor.first()
while rec:
    print rec
    rec = cursor.next()
fruitDB.close()

