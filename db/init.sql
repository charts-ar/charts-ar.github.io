-- users and authentication
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  verified BOOLEAN DEFAULT FALSE,
  role VARCHAR(20) DEFAULT 'user', -- 'user', 'room_owner', 'admin'
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE verification_tokens (
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  token TEXT UNIQUE NOT NULL,
  expires_at TIMESTAMP NOT NULL
);

CREATE TABLE password_reset_tokens (
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  token TEXT UNIQUE NOT NULL,
  expires_at TIMESTAMP NOT NULL
);

-- device‑cache tracking for bans/mutes
CREATE TABLE device_idents (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT UNIQUE NOT NULL, -- unique per device (store in localStorage perhaps)
  first_seen TIMESTAMP DEFAULT NOW()
);

CREATE TABLE global_bans (
  device_id TEXT UNIQUE NOT NULL,
  banned_at TIMESTAMP DEFAULT NOW(),
  reason TEXT
);

-- chatrooms
CREATE TABLE chatrooms (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  description TEXT,
  owner_user_id INTEGER REFERENCES users(id),
  max_users INTEGER DEFAULT 100,
  is_private BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT NOW()
);

-- room‑specific bans/mutes
CREATE TABLE room_bans (
  chatroom_id INTEGER REFERENCES chatrooms(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  banned_at TIMESTAMP DEFAULT NOW(),
  reason TEXT,
  PRIMARY KEY(chatroom_id, device_id)
);

CREATE TABLE room_mutes (
  chatroom_id INTEGER REFERENCES chatrooms(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  muted_until TIMESTAMP NOT NULL,
  reason TEXT,
  PRIMARY KEY(chatroom_id, device_id)
);

-- messages (chatrooms)
CREATE TABLE room_messages (
  id SERIAL PRIMARY KEY,
  chatroom_id INTEGER REFERENCES chatrooms(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id),
  device_id TEXT NOT NULL,
  content TEXT,
  image_url TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

-- direct messages (DMs)
CREATE TABLE direct_threads (
  id SERIAL PRIMARY KEY,
  user1_id INTEGER REFERENCES users(id),
  user2_id INTEGER REFERENCES users(id),
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(user1_id, user2_id)
);

CREATE TABLE direct_messages (
  id SERIAL PRIMARY KEY,
  thread_id INTEGER REFERENCES direct_threads(id) ON DELETE CASCADE,
  sender_user_id INTEGER REFERENCES users(id),
  sender_device_id TEXT NOT NULL,
  content TEXT,
  image_url TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

-- moderation logs
CREATE TABLE moderation_logs (
  id SERIAL PRIMARY KEY,
  action_type VARCHAR(50) NOT NULL, -- 'delete_message', 'ban_global', 'ban_room', 'mute_room', 'kick_user', 'delete_chatroom', 'report_resolved'
  actor_user_id INTEGER REFERENCES users(id),
  target_user_id INTEGER REFERENCES users(id),
  target_device_id TEXT,
  chatroom_id INTEGER REFERENCES chatrooms(id),
  message_id INTEGER,
  reason TEXT,
  timestamp TIMESTAMP DEFAULT NOW()
);
