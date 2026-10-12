const db = require("./db");

// Removes a user and everything that belongs to them, children first (foreign keys are enforced).
// Used by self-service account deletion and by admins deleting a user.
function deleteUserAndData(userId) {
  db.exec("BEGIN");
  try {
    const own = "(SELECT id FROM servers WHERE user_id = ?)";
    db.prepare(`DELETE FROM ssh_logs WHERE server_id IN ${own}`).run(userId);
    db.prepare(`DELETE FROM incidents WHERE server_id IN ${own}`).run(userId);
    db.prepare("DELETE FROM servers WHERE user_id = ?").run(userId);
    db.prepare("DELETE FROM registrations WHERE user_id = ?").run(userId);
    db.prepare("DELETE FROM logins WHERE user_id = ?").run(userId);
    db.prepare("DELETE FROM users WHERE id = ?").run(userId);
    db.exec("COMMIT");
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
}

module.exports = { deleteUserAndData };
