const express = require('express');
const multer = require('multer');
const hbs = require('hbs');
const mysql = require('mysql'); 
const path = require('path');

const bcrypt = require('bcryptjs');
const saltRounds = 10;

const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const expressValidator = require('express-validator');
const flash = require('connect-flash');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const moment = require('moment');
const fs = require('fs'); 
var csv = require('fast-csv');
var random = require("randomstring");

var name,addr;

const app = express();
const port = 10000;

// CORS
app.use(function(req, res, next) {
	res.header("Access-Control-Allow-Origin", "*");
	res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
	res.header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE, PUT");
	next();
})

// Body parser
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true}));
app.use(cookieParser());

// Database
var con = mysql.createConnection({
	host: "localhost",
	user: "root",
	password: "Tracking2018",
	database: "checktracking",
	multipleStatements: true
});
con.connect(function(err) {
	if(err) throw err;
	console.log("Connected to database!");
});

var options = {
	host: 'localhost',
	port: 3306,
	user: 'root',
	password: 'Tracking2018',
	database: 'checktracking'
};

var sessionStore = new MySQLStore(options);

// Session
app.use(session({
	secret: 'mySecret',
	store: sessionStore,
	saveUninitialized: true,
	resave: true
}));

// Flash
app.use(flash());
app.use(function(req, res, next) {
	res.locals.success_msg = req.flash('success_msg');
	res.locals.error_msg = req.flash('error_msg');
	res.locals.error = req.flash('error');
	next();
});

// Express Validator
app.use(expressValidator({
	errorFormatter: function(param, msg, value) {
		var namespace = param.split('.')
		, root = namespace.shift()
		, formParam = root;

		while(namespace.length) {
			formParam += '[' + namespace.shift() + ']';
		}

		return {
			param: formParam,
			msg: msg,
			value: value
		};
	}
}));

// Passport
app.use(passport.initialize());
app.use(passport.session());
app.use(function(req, res, next) {
	res.locals.isAuthenticated = req.isAuthenticated();
	next();
});

// View Engine
app.set('view engine', 'hbs');
app.use(express.static('./public'));
hbs.registerPartials(__dirname + '/views/includes');

// Index
app.get('/', function(req, res) {
	var sql = "SELECT * FROM store";
	con.query(sql, function (err, result, fields) {
		if (err) done(err);
		res.render('index',{
			stores: result
		});
	});
});

// Login
app.get('/login', function(req, res) {
	if(req.isAuthenticated()) res.redirect('/');
	else res.render('login');
});

passport.use(new LocalStrategy(
	function(email, pwd, done) {
		var sql = "SELECT * FROM member natural join store WHERE member_email = " + con.escape(email);
		con.query(sql, function (err, result, fields) {
			if (err) done(err);
			if(result.length === 0) {
				done(null, false, { message: 'อีเมลล์ / พาสเวิร์ด ไม่ถูกต้อง' });
			} else {
				const hash = result[0].member_pwd;
				
				bcrypt.compare(pwd, hash, function(err, res) {
					if(res === true) {
						return done(null, result);
					} else {
						return done(null, false, { message: 'อีเมลล์ / พาสเวิร์ด ไม่ถูกต้อง' });
					}
				});
			}

		});
	}
));
	
passport.serializeUser(function(member_id, done) {
	done(null, member_id);
});

passport.deserializeUser(function(member_id, done) {
	done(null, member_id);
});

function authMiddleware(req, res, next) {
	if(req.isAuthenticated()) return next();
	res.redirect('/login');
}

app.post('/login', passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login', failureFlash : true }),function(req, res) {
	res.redirect('/member');
});

// Logout
app.get('/logout', function(req, res) {
	req.logout();
	req.session.destroy();
	res.redirect('/');
});

// Register
app.get('/register', function(req, res) {
	res.render('register');
});

app.post('/register', function(req, res) {
	var email =  req.body.email;
	var pwd =  req.body.pwd;
	var pwdcf =  req.body.pwdcf;
	var fname =  req.body.fname;
	var lname =  req.body.lname;
	var store_name =  req.body.store_name;
	var store_uname =  req.body.store_uname;

	// Validation
	req.checkBody('email', 'Email is required').isEmail();
	req.checkBody('pwd', 'Password is required').notEmpty();
	req.checkBody('fname', 'Firstname is required').notEmpty();
	req.checkBody('lname', 'Lastname is required').notEmpty();
	req.checkBody('store_name', 'Store name is required').notEmpty();
	req.checkBody('store_uname', 'Store username is required').notEmpty();
	req.checkBody('pwdcf', 'Password do not match').equals(pwd);

	var errors = req.validationErrors();
	if(errors) {
		res.render('register', {
			errors: errors
		});
	} else {
		var sql = "SELECT * FROM member WHERE member_email = " + con.escape(email);
		con.query(sql, function (err, result, fields) {
			if (err) throw err;

			if(result.length > 1) {

				res.render('register', {
					errors: [{msg: 'อีเมลล์นี้ถูกใช้งานแล้ว'}]
				});

			} else {

				var stamp = moment(Date.now()).format('YYYY-MM-DD HH:mm:ss');
				con.beginTransaction(function(err) {
					if (err) throw err;
					bcrypt.hash(pwd, saltRounds, function(err, hash) {
						var sql = "INSERT INTO store (store_uname, store_name, store_detail, store_img_1, store_stamp) VALUES (" + con.escape(store_uname) + ", " + con.escape(store_name) + ", '', '', '" + stamp + "')";
						con.query(sql, function (err, results, fields) {
							if (err) {
								return con.rollback(function() {
									throw err;
								});
							}
							//var inserted = results.insertId;
							var sql = "INSERT INTO member (member_id, member_email, member_pwd, member_fname, member_lname, member_stamp, store_uname) VALUES (0, " + con.escape(email) + ", " + con.escape(hash) + ", " + con.escape(fname) + ", " + con.escape(lname) + ", '" + stamp + "', " + con.escape(store_uname) + ")";
							con.query(sql, function (err, results, fields) {
								if (err) {
								 	return con.rollback(function() {
								 		throw err;
								 	});
								}
							});

							con.commit(function(err) {
								if (err) {
									return connection.rollback(function() {
										throw err;
									});
								}
								req.flash('success_msg', 'สมัครสมาชิกเรียบร้อย คุณสามารถเข้าสู่ระบบได้เลย');
								res.redirect('login');
							});
						});
					});
				});

			}
		});
	}
});

// Store
app.get('/store/:store', function(req, res) {
	var store = req.params.store;
	var sql = "SELECT * FROM store WHERE store_uname = " + con.escape(store);
	con.query(sql, function (err, result_store, fields) {
		if (err) throw err;
		
		if(result_store.length == 1) {
			res.render('store', {
				store: result_store[0],
			});
		} else {
			res.render('store', {
				error: 'ไม่พบร้านค้า'
			});
		}
	});
});

app.get('/store/:store/search', function(req, res) {
	var store = req.params.store;
	var sql = "SELECT * FROM store WHERE store_uname = " + con.escape(store);
	con.query(sql, function (err, result_store, fields) {
		if (err) throw err;
		
		if(result_store.length == 1) {
			var sql_list = "SELECT * FROM tracking_1 WHERE store_uname = " + con.escape(store);
			con.query(sql_list, function (err, result_list, fields) {
				if (err) throw err;
				res.render('store', {
					store: result_store[0],
					list: result_list,
					search: true
				});
			});
		} else {
			res.render('store', {
				error: 'ไม่พบร้านค้า'
			});
		}
	});
});

app.get('/store/:store/search/:key', function(req, res) {
	var store = req.params.store;
	var key = req.params.key;
	var sql = "SELECT * FROM store WHERE store_uname = " + con.escape(store);
	con.query(sql, function (err, result_store, fields) {
		if (err) throw err;
		
		if(result_store.length == 1) {
			var sql_list = "SELECT * FROM tracking_1 WHERE store_uname = " + con.escape(store) + " AND (list_fname LIKE '%" + key + "%' OR list_lname LIKE '%" + key + "%')";
			con.query(sql_list, function (err, result_list, fields) {
				if (err) throw err;
				res.render('store', {
					store: result_store[0],
					list: result_list,
					search: true,
					key: key
				});
			});
		} else {
			res.render('store', {
				error: 'ไม่พบร้านค้า'
			});
		}
	});
});

// Member
app.get('/member', authMiddleware, function(req, res) {
	var sql = "SELECT * FROM store WHERE store_uname = " + con.escape(req.user[0].store_uname);
	con.query(sql, function (err, result_store, fields) {
		if (err) throw err;
		
		if(result_store.length == 1) {
			res.render('member', {
				user: req.user[0],
				store: result_store[0]
			});
		} else {
			res.render('member', {
				user: req.user[0],
				store: {
					store_uname: req.user[0].store_uname
				}
			});
		}
	});
});

const storage_logo = multer.diskStorage({
  destination: function (req, file, cb) {
  	addr = './public/uploads/logo/';
    cb(null, addr)
  },
  filename: function (req, file, cb) {
  	name = random.generate({
  		length: 12,
  		charset: 'abcdefghijklmnopqrstuvwxyz0123456789'
  	}) + '_' + Date.now() + path.extname(file.originalname);
    cb(null, name)
  }
});

const upload_logo = multer({
	storage: storage_logo,
	limit: {
		fileSize: 1000000
	},
	fileFilter: function(req, file, cb) {
		checkFile_logo(file, cb);
	}
}).single('logoUpload');

function checkFile_logo(file, cb) {
	const filetypes = /png|jpeg|jpg/;
	const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
	//const mimetype = filetypes.test(file.mimetype);

	if(extname) {
		return cb(null, true);
	} else {
		cb('ไฟล์ PNG, JPEG, JPG เท่านั้น');
	}
}

app.post('/member', authMiddleware, function(req, res) {
	upload_logo(req, res, (err) => {
		var action = req.body.action;
		if(action == "edit_logo") {
			if(err) {
				res.render('member', {
					user: req.user[0],
					store: req.user[0],
					error: err
				});
			} else {
				console.log(name);
				if(req.file == undefined) {
					res.render('member', {
						user: req.user[0],
						store: req.user[0],
						error: 'กรุณาเลือกไฟล์'
					});
				} else {
					var query = con.query("UPDATE store SET store_img_1 = " + con.escape('/uploads/logo/' + name) + " WHERE store_uname = " + con.escape(req.user[0].store_uname), function(err, result) {
						if(err) {
							res.render('member', {
								user: req.user[0],
								store: req.user[0],
								error: err
							});
						} else {
							res.redirect('/member');
						}
					});
				}
			}
		} else if(action == "edit_detail") {
			if(req.body.store_name.length <= 0) {
				res.render('member', {
					user: req.user[0],
					store: req.user[0],
					error: 'กรุณากรอกชื่อร้านค้า'
				});
			} else if(req.body.store_detail.length <= 0) {
				res.render('member', {
					user: req.user[0],
					store: req.user[0],
					error: 'กรุณากรอกรายละเอียดร้านค้า'
				});
			} else {
				var query = con.query("UPDATE store SET store_name = " + con.escape(req.body.store_name) + ", store_detail = " + con.escape(req.body.store_detail) + " WHERE store_uname = " + con.escape(req.user[0].store_uname), function(err, result) {
					if(err) {
						res.render('member', {
							user: req.user[0],
							store: req.user[0],
							error: err
						});
					} else {
						res.render('member', {
							user: req.user[0],
							success_msg: 'บันทึกข้อมูลเรียบร้อย',
							store: {
								store_uname: req.user[0].store_uname,
								store_name: req.body.store_name,
								store_detail: req.body.store_detail
							},
						});
					}
				});
			}
		} else {
			res.render('member', {
				user: req.user[0],
				store: req.user[0],
				error: "ไม่มีการทำรายการ"
			});
		}
	})
});

// Edit
app.get('/edit', authMiddleware, function(req, res) {
	var store = req.user[0].store_uname;
	var sql = "SELECT * FROM store WHERE store_uname = " + con.escape(store);
	con.query(sql, function (err, result_store, fields) {
		if (err) throw err;
		
		if(result_store.length == 1) {
			res.render('edit', {
				store: result_store[0],
			});
		} else {
			res.render('store', {
				error: 'ไม่พบร้านค้า'
			});
		}
	});
});

const storage_edit = multer.diskStorage({
	destination: function (req, file, cb) {
		var store_uname = req.params.store_uname;
		var addr = './public/uploads/store/' + store_uname;
		cb(null, addr)
	},
	filename: function (req, file, cb) {
	  	name = req.params.action + '_' + random.generate({
	  		length: 6,
	  		charset: 'abcdefghijklmnopqrstuvwxyz'
	  	}) + '_' + Date.now() + path.extname(file.originalname);
	    cb(null, name)
  	}
});

const upload_edit = multer({
	storage: storage_edit,
	limit: {
		fileSize: 1000000
	},
	fileFilter: function(req, file, cb) {
		checkFile_edit(file, cb);
	}
}).any();

function checkFile_edit(file, cb) {
	const filetypes = /png|jpeg|jpg/;
	const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
	//const mimetype = filetypes.test(file.mimetype);

	if(extname) {
		return cb(null, true);
	} else {
		cb('ไฟล์ PNG, JPEG, JPG เท่านั้น');
	}
}

app.post('/edit/:store_uname/:action', authMiddleware, function(req, res) {
	var store_uname = req.params.store_uname;
	var action = req.params.action;

	var addr = './public/uploads/store/' + store_uname;
	if(!fs.existsSync(addr)){
	    fs.mkdirSync(addr);
	}

	upload_edit(req, res, (err) => {
		if(err) {
			res.send(err);
			return;
		}
		
		if(action == 'logo') {
			var files = req.files;
			if(files.length > 0){
				var path = '/uploads/store/' + store_uname + '/' + files[0].filename;
				var query = con.query("UPDATE store SET store_img_1 = " + con.escape(path) + " WHERE store_uname = " + con.escape(req.user[0].store_uname), function(err, result) {
					if(err) res.send('ไม่สามารถบันทึกรายการได้')
					else res.send(true);
				});
			} else {
				res.send('กรุณาเลือกไฟล์');
			}
		} else if(action == 'store_name') {
			var query = con.query("UPDATE store SET store_name = " + con.escape(req.body.store_name) + ", store_detail = " + con.escape(req.body.store_detail) + " WHERE store_uname = " + con.escape(req.user[0].store_uname), function(err, result) {
				if(err) res.send('ไม่สามารถบันทึกรายการได้')
				else res.send(true);
			});
		} else if(action == 'line') {
			var query = con.query("UPDATE store SET store_line_id = " + con.escape(req.body.store_line_id) + ", store_line_link = " + con.escape(req.body.store_line_link) + " WHERE store_uname = " + con.escape(req.user[0].store_uname), function(err, result) {
				if(err) res.send('ไม่สามารถบันทึกรายการได้')
				else res.send(true);
			});
		} else if(action == 'fb') {
			var query = con.query("UPDATE store SET store_fb_uname = " + con.escape(req.body.store_fb_uname) + ", store_fb_link = " + con.escape(req.body.store_fb_link) + " WHERE store_uname = " + con.escape(req.user[0].store_uname), function(err, result) {
				if(err) res.send('ไม่สามารถบันทึกรายการได้')
				else res.send(true);
			});
		} else if(action == 'ig') {
			var query = con.query("UPDATE store SET store_ig_uname = " + con.escape(req.body.store_ig_uname) + ", store_ig_link = " + con.escape(req.body.store_ig_link) + " WHERE store_uname = " + con.escape(req.user[0].store_uname), function(err, result) {
				if(err) res.send('ไม่สามารถบันทึกรายการได้')
				else res.send(true);
			});
		} else if(action == 'gal_1' || action == 'gal_2' || action == 'gal_3') {
			var col = "store_" + action + "_img";
			var files = req.files;
			var path = '/uploads/store/' + store_uname + '/' + files[0].filename;
			var query = con.query("UPDATE store SET " + col + " = " + con.escape(path) + " WHERE store_uname = " + con.escape(req.user[0].store_uname), function(err, result) {
				if(err) res.send('ไม่สามารถบันทึกรายการได้')
				else res.send(true);
			});
		} else {
			res.send(false);
		}
		
	});

});

// Upload
app.get('/upload', authMiddleware, function(req, res) {
	res.render('upload');
});

const storage_fileCSV = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './public/uploads')
  },
  filename: function (req, file, cb) {
  	var name = random.generate({
  		length: 12,
  		charset: 'abcdefghijklmnopqrstuvwxyz0123456789'
  	});
    cb(null, name + '_' + Date.now() + path.extname(file.originalname))
  }
});

const upload_fileCSV = multer({
	storage: storage_fileCSV,
	limit: {
		fileSize: 1000000
	},
	fileFilter: function(req, file, cb) {
		checkFile_fileCSV(file, cb);
	}
}).single('fileUpload');

function checkFile_fileCSV(file, cb) {
	const filetypes = /csv/;
	const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
	//const mimetype = filetypes.test(file.mimetype);

	if(extname) {
		return cb(null, true);
	} else {
		cb('ไฟล์ CSV เท่านั้น');
	}
}

app.post('/upload', authMiddleware, function(req, res) {
	var set = [];
	upload_fileCSV(req, res, (err) => {
		if(err) {
			res.render('upload', {
				error: err
			});
		} else {
			if(req.file == undefined) {
				res.render('upload', {
					error: 'กรุณาเลือกไฟล์'
				});
			} else {
				var stamp = moment(Date.now()).format('YYYY-MM-DD HH:mm:ss');
				var stream = fs.createReadStream(req.file.path);
				csv.fromStream(stream,{ headers : true, ignoreEmpty: true })
				.on("data", function(data){
					//console.log(data);
					//list_id, list_fname, list_lname, list_track_no, list_track_type, list_stamp, store_id
					set.push([0, data.firstname, data.lastname, data.tracking_number, data.tracking_type, stamp, req.user[0].store_uname]);
				})
				.on("end", function(){
					console.log(set);
					var post  = set;
					var query = con.query('INSERT INTO tracking_1 VALUES ?', [post], function(err, result) {
						if(err) {
							res.render('upload', {
								error: err
							});
						} else {
							res.render('upload', {
								success_msg: 'อัพโหลดไฟล์เรียบร้อย',
								dat: set,
							});
						}
					});
				});
			}
		}
	})
});

app.listen(port, function() {
	console.log('Server is running on port ' + port);
});