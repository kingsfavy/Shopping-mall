

let db = (`CREATE TABLE wallet (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      balance INTEGER NOT NULL,
      transactions TEXT NOT NULL
    )`, (err) => {
      if (err) {
        console.error('Error creating table:', err.message);
      } else {
        console.log('Wallet table created.');
        // Initialize wallet with zero balance and empty transactions
        db.run(`INSERT INTO wallet (balance, transactions) VALUES (0, '[]')`);
      }
    });
  


module.exports = db;