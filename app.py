import os, random, sendgrid
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db, Admin, Customer, Order, Bill
from utils import generate_auid, generate_cuid, generate_order_id, generate_bill_id, now_str, items_to_json, items_from_json
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from PIL import Image
from dotenv import load_dotenv
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


UPLOAD_FOLDER = os.path.join('instance', 'uploads')
ALLOWED_EXT = set(['png','jpg','jpeg','gif','pdf','doc','docx'])

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

load_dotenv()
attempts = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
    app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT"))
    app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS") == "True"
    app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
    app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER")
    db.init_app(app)
    mail = Mail(app)

    with app.app_context():
        db.create_all()

    # ----- helpers / decorators -----
    def admin_required(f):
        from functools import wraps
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get('role') != 'admin' or not session.get('admin_id'):
                flash("Admin login required", "warning")
                return redirect(url_for('admin_login'))
            return f(*args, **kwargs)
        return decorated

    def customer_required(f):
        from functools import wraps
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get('role') != 'customer' or not session.get('customer_id'):
                flash("Customer login required", "warning")
                return redirect(url_for('customer_login'))
            return f(*args, **kwargs)
        return decorated

    # ----- routes -----
    @app.route('/')
    def home():
        return render_template('home.html')
    
    @app.route("/admin/security", methods=["GET", "POST"])
    def admin_security():
        key_id = "admin_security"

        # Check if blocked
        if not check_rate_limit(key_id):
            # ❌ DO NOT redirect (causes loop)
            # return redirect(url_for("admin_security"))

            flash("Too many attempts! Try again after 5 minutes.", "danger")
            return render_template("admin_key.html")   # <-- FIXED

        if request.method == "POST":
            entered = request.form.get("secret_key")

            if entered == os.getenv("ADMIN_SECURITY_KEY"):
                attempts[key_id] = {"count": 0, "block_until": None}  # reset
                session["admin_access"] = True
                return redirect(url_for("admin_login"))

            # Wrong key
            record_failed_attempt(key_id)
            flash("Invalid security key!", "danger")
            return render_template("admin_key.html")   # also prevent loops

        return render_template("admin_key.html")
    
    def send_email_otp(to_email, otp):
        sg = sendgrid.SendGridAPIClient(api_key=os.getenv("SENDGRID_API_KEY"))
        message = Mail(
            from_email=os.getenv("FROM_EMAIL"),
            to_emails=to_email,
            subject="Sri Vinayaga Stores - Admin OTP",
            html_content=f"<h3>Your OTP is: <b>{otp}</b></h3>"
                        f"<p>This OTP will expire in 5 minutes.</p>"
        )
        sg.send(message)

    
    @app.route("/admin/resend-otp")
    def send_admin_otp():
        email = session.get("admin_email")

        if not email:
            flash("Session expired! Please sign up again.", "danger")
            return redirect(url_for("admin_signup"))

        # Generate new OTP
        new_otp = str(random.randint(100000, 999999))
        session["admin_otp"] = new_otp

        # Send OTP
        msg = Message("Your Admin OTP",
                    recipients=[email])
        msg.body = f"Your new OTP is: {new_otp}"
        mail.send(msg)

        flash("A new OTP has been sent!", "success")
        return redirect(url_for("admin_verify_otp"))

    
    @app.route("/admin/resend-otp")
    def admin_resend_otp():
        data = session.get("pending_admin")

        if not data:
            flash("Session expired. Please sign up again.", "danger")
            return redirect(url_for("admin_signup"))

        email = data["email"]

        # New OTP
        new_otp = random.randint(100000, 999999)
        session["pending_admin"]["otp"] = new_otp

        # Send with SendGrid
        send_email_otp(email, new_otp)

        flash("A new OTP has been sent to your email!", "success")
        return redirect(url_for("admin_verify_otp"))


    
    def check_rate_limit(key):
        """Returns True if allowed, False if blocked."""
        info = attempts.get(key)

        if info:
            # If blocked
            if info.get("block_until") and datetime.now() < info["block_until"]:
                return False
            
            # If 3 attempts already happened but block time expired → reset
            if info["count"] >= 3:
                attempts[key] = {"count": 0, "block_until": None}

        return True


    def record_failed_attempt(key):
        """Records bad attempts and triggers block."""
        info = attempts.get(key, {"count": 0, "block_until": None})
        info["count"] += 1

        if info["count"] >= 3:
            info["block_until"] = datetime.now() + timedelta(minutes=5)

        attempts[key] = info


    # ----- Admin signup/login/dashboard -----
    @app.route("/admin/signup", methods=["GET", "POST"])
    def admin_signup():
        # Security key check
        if not session.get("admin_access"):
            return redirect(url_for("admin_security"))

        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            mobile = request.form.get('mobile')
            password = request.form.get('password')

            # Validate
            if not (name and email and mobile and password):
                flash("Please fill all fields", "danger")
                return redirect(url_for('admin_signup'))

            if Admin.query.filter_by(email=email).first():
                flash("Email already exists", "danger")
                return redirect(url_for('admin_signup'))

            # Generate OTP
            otp = random.randint(100000, 999999)

            # Store temporary signup data in session
            session["pending_admin"] = {
                "name": name,
                "email": email,
                "mobile": mobile,
                "password_hash": generate_password_hash(password),
                "otp": otp
            }

            # Send OTP via SendGrid
            send_email_otp(email, otp)

            flash("OTP sent to your email!", "success")
            return redirect(url_for("admin_verify_otp"))

        return render_template("admin_signup.html")

    
    @app.route("/admin/verify-otp", methods=["GET", "POST"])
    def admin_verify_otp():
        data = session.get("pending_admin")

        if not data:
            flash("Session expired. Please sign up again.", "danger")
            return redirect(url_for("admin_signup"))

        if request.method == "POST":
            entered_otp = request.form.get("otp")

            if str(entered_otp) == str(data["otp"]):
                auid = generate_auid()

                new_admin = Admin(
                    name=data["name"],
                    email=data["email"],
                    mobile=data["mobile"],
                    password_hash=data["password_hash"],
                    auid=auid
                )

                db.session.add(new_admin)
                db.session.commit()

                session.pop("pending_admin")  # cleanup

                flash(f"Admin account created successfully! Your AUID: {auid}", "success")
                return redirect(url_for("admin_login"))

            flash("Incorrect OTP! Try again.", "danger")

        return render_template("admin_verify_otp.html")



    @app.route('/admin/login', methods=['GET','POST'])
    def admin_login():
        key_id = "admin_login"

        # If blocked due to too many attempts
        if not check_rate_limit(key_id):
            flash("Too many failed login attempts! Try again after 5 minutes.", "danger")
            return render_template('admin_login.html')  # NO REDIRECT → FIX LOOP

        if request.method == 'POST':
            identifier = request.form.get('identifier')  # email or AUID
            password = request.form.get('password')

            admin = Admin.query.filter(
                (Admin.email == identifier) | (Admin.auid == identifier)
            ).first()

            # Correct login
            if admin and check_password_hash(admin.password_hash, password):
                attempts[key_id] = {"count": 0, "block_until": None}  # reset attempts

                session.clear()
                session['role'] = 'admin'
                session['admin_id'] = admin.id
                session['admin_name'] = admin.name
                flash("Admin logged in", "success")
                return redirect(url_for('admin_dashboard'))

            # Wrong login → record attempt
            record_failed_attempt(key_id)
            flash("Invalid credentials!", "danger")

            return render_template('admin_login.html')  # NO REDIRECT → FIX LOOP

        return render_template('admin_login.html')



    @app.route('/admin/logout')
    def admin_logout():
        session.clear()
        flash("Logged out", "info")
        return redirect(url_for('home'))

    @app.route('/admin/dashboard')
    @admin_required
    def admin_dashboard():
        admin = Admin.query.get(session['admin_id'])
        orders = Order.query.order_by(Order.created_at.desc()).all()
        bills = Bill.query.order_by(Bill.created_at.desc()).all()
        return render_template('admin_dashboard.html', admin=admin, orders=orders, bills=bills)

    @app.route('/admin/upload_qr', methods=['POST'])
    @admin_required
    def admin_upload_qr():
        qr_file = request.files.get('qr')

        if qr_file:
            filename = "qr_code.png"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            qr_file.save(filepath)

            session['qr_uploaded'] = True
            flash("QR Code uploaded successfully", "success")

        return redirect(url_for('admin_dashboard'))

    
    @app.route('/admin/update', methods=['GET', 'POST'])
    @admin_required
    def admin_update():
        admin = Admin.query.get(session['admin_id'])

        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            mobile = request.form.get('mobile')

            existing = Admin.query.filter_by(email=email).first()
            if existing and existing.id != admin.id:
                flash("Email already taken", "danger")
                return redirect(url_for('admin_update'))

            admin.name = name
            admin.email = email
            admin.mobile = mobile

            db.session.commit()
            session['admin_name'] = name
            flash("Profile updated successfully", "success")
            return redirect(url_for('admin_dashboard'))

        return render_template('admin_update.html', admin=admin)

    @app.route('/admin/delete', methods=['POST'])
    @admin_required
    def admin_delete():
        admin = Admin.query.get(session['admin_id'])

        bills = Bill.query.filter_by(admin_id=admin.id).all()
        for b in bills:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], b.pdf_filename))
            except:
                pass
            db.session.delete(b)

        db.session.delete(admin)
        db.session.commit()

        session.clear()
        flash("Admin account deleted permanently.", "info")
        return redirect(url_for('home'))
    

    @app.route('/admin/delete-bill/<bill_id>', methods=['POST'])
    def delete_bill(bill_id):
        # Fetch the bill by bill_id
        bill = Bill.query.filter_by(bill_id=bill_id).first()
        if not bill:
            flash("Bill not found!", "danger")
            return redirect(url_for('admin_dashboard'))  # Change to your admin dashboard route

        try:
            db.session.delete(bill)
            db.session.commit()
            flash("Bill deleted successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error deleting bill: {str(e)}", "danger")

        return redirect(url_for('admin_dashboard'))

    @app.route("/admin/forgot-password", methods=["GET", "POST"])
    def admin_forgot_password():
        if request.method == "POST":
            email = request.form["email"]
            new_password = request.form["new_password"]
            confirm_password = request.form["confirm_password"]

            if new_password != confirm_password:
                flash("Passwords do not match!", "error")
                return redirect(url_for("admin_forgot_password"))

            admin = Admin.query.filter_by(email=email).first()
            if not admin:
                flash("Admin email not found!", "error")
                return redirect(url_for("admin_forgot_password"))

            admin.password_hash = generate_password_hash(new_password)   # FIXED
            db.session.commit()

            flash("Password changed successfully!", "success")
            return redirect(url_for("admin_login"))

        return render_template("admin_forgot_password.html")


    @app.route("/admin/customers")
    def admin_customers():
        if session.get('role') != 'admin':
            flash("Unauthorized access!", "danger")
            return redirect(url_for('admin_login'))

        customers = Customer.query.all()
        return render_template("admin_customers.html", customers=customers)



    # admin change order status
    @app.route('/admin/order/<int:order_id>/status', methods=['POST'])
    @admin_required
    def admin_change_status(order_id):
        st = request.form.get('status')
        order = Order.query.get_or_404(order_id)
        if st in ['Received','Packed','Pending']:
            order.status = st
            db.session.commit()
            flash("Order status updated", "success")
        else:
            flash("Invalid status", "danger")
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/order/<int:order_id>/delete', methods=['POST'])
    @admin_required
    def admin_delete_order(order_id):
        order = Order.query.get_or_404(order_id)
        # remove uploaded file if any
        if order.uploaded_filename:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], order.uploaded_filename))
            except:
                pass
        db.session.delete(order)
        db.session.commit()
        flash("Order deleted", "info")
        return redirect(url_for('admin_dashboard'))
    
    @app.route("/admin/delete-customer/<int:customer_id>", methods=["POST"])
    def delete_customer(customer_id):
        if session.get("role") != "admin":
            flash("Unauthorized access!", "danger")
            return redirect(url_for("admin_login"))

        customer = Customer.query.get(customer_id)

        if not customer:
            flash("Customer not found!", "error")
            return redirect(url_for("admin_customers"))

        db.session.delete(customer)
        db.session.commit()

        flash("Customer deleted successfully!", "success")
        return redirect(url_for("admin_customers"))


    # billing page for admin
    @app.route('/admin/billing/<int:order_id>', methods=['GET','POST'])
    @admin_required
    def billing(order_id):
        order = Order.query.get_or_404(order_id)
        if request.method == 'POST':
            # items are sent as repeated fields item_name[], qty[], price[]
            names = request.form.getlist('item_name[]')
            qtys = request.form.getlist('item_qty[]')
            prices = request.form.getlist('item_price[]')
            items = []
            total = 0.0
            for n,q,p in zip(names, qtys, prices):
                try:
                    price_val = float(p)
                except:
                    price_val = 0.0
                items.append({"name": n, "qty": q, "price": price_val})
                total += price_val
            bill_id = generate_bill_id()
            admin = Admin.query.get(session['admin_id'])
            bill = Bill(bill_id=bill_id, order_id=order.order_id, admin_id=admin.id,
                        items_json=items_to_json(items),
                        total_amount=total)
            # generate PDF now
            pdf_name = f"{bill_id}.pdf"
            pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_name)
            create_bill_pdf(app, bill, order, pdf_path)
            bill.pdf_filename = pdf_name
            db.session.add(bill)
            db.session.commit()
            flash("Bill generated", "success")
            return redirect(url_for('admin_dashboard'))
        return render_template('billing.html', order=order)

    def create_bill_pdf(app, bill, order, pdf_path):
        """
        bill: Bill model (not committed yet)
        order: Order model
        pdf_path: full filesystem path where to save
        """
        customer = Customer.query.filter_by(id=order.customer_id).first()

        c = canvas.Canvas(pdf_path, pagesize=A4)
        width, height = A4

        # ================= HEADER =================
        c.setFont("Helvetica-Bold", 18)
        c.drawCentredString(width / 2, height - 50, "Sri Vinayaga Stores")

        # NEW shop address line
        c.setFont("Helvetica", 12)
        c.drawCentredString(width / 2, height - 70, "Pillaiyar Kuppam, Vellore - 09.")

        # Bill and Order Info
        c.setFont("Helvetica", 10)
        c.drawString(50, height - 95, f"Bill ID: {bill.bill_id}")
        c.drawString(50, height - 110, f"Order ID: {order.order_id}")
        c.drawString(50, height - 125, f"Date: {now_str()}")

        # ================= CUSTOMER =================
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, height - 155, "Customer Details")

        c.setFont("Helvetica", 10)
        c.drawString(50, height - 170, f"Name: {customer.name if customer else ''}")
        c.drawString(50, height - 185, f"Mobile: {customer.mobile if customer else ''}")
        c.drawString(50, height - 200, f"Address: {customer.address if customer else ''}")

        # ================= ITEMS =================
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, height - 230, "Items")

        c.setFont("Helvetica", 10)
        y = height - 250

        c.drawString(50, y, "S.No")
        c.drawString(90, y, "Item")
        c.drawString(350, y, "Qty")
        c.drawString(430, y, "Price")
        y -= 15

        items = items_from_json(bill.items_json)
        i = 1

        for it in items:
            c.drawString(50, y, str(i))
            c.drawString(90, y, str(it.get('name', '')))
            c.drawString(350, y, str(it.get('qty', '')))
            c.drawString(430, y, f"{it.get('price', 0):.2f}")

            y -= 15
            i += 1

            # New page if needed
            if y < 120:
                c.showPage()
                y = height - 100

        # ================= TOTAL AMOUNT =================
        # slightly moved left & above QR area
        c.setFont("Helvetica-Bold", 12)
        c.drawString(300, y - 5, "Total Amount: Rs.")
        c.drawString(420, y - 5, f"{bill.total_amount:.2f}")

        # ================= QR CODE =================
        try:
            files = os.listdir(app.config['UPLOAD_FOLDER'])
            qr_candidates = [f for f in files if 'qr' in f.lower()]

            if qr_candidates:
                qr_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_candidates[0])

                qr_size = 110  # bigger QR

                # Move Scan & Pay UP (higher)
                c.setFont("Helvetica-Bold", 12)
                c.drawString(50, 170, "Scan & Pay")   # previously 120 → now 170

                # Add gap between Scan & Pay and QR (QR lower)
                img = Image.open(qr_path)
                img_reader = ImageReader(img)

                c.drawImage(
                    img_reader,
                    50,
                    40,      # previously 10 → now 40 (moves QR up but leaves gap)
                    width=qr_size,
                    height=qr_size,
                    preserveAspectRatio=True
                )

        except Exception as e:
            pass


        # ================= FOOTER =================
        c.setFont("Helvetica-Bold", 10)
        c.drawCentredString(
            width / 2,
            20,
            "Thanks for Ordering & Keep Purchasing - Sri Vinayaga Stores - Pillaiyar Kuppam, Vellore - 09."
        )

        c.save()

    # serve uploaded files for download viewing
    @app.route('/uploads/<path:filename>')
    def uploaded_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

    # ----- Customer signup/login/dashboard -----
    @app.route('/customer/signup', methods=['GET', 'POST'])
    def customer_signup():
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            mobile = request.form.get('mobile')
            address = request.form.get('address')
            password = request.form.get('password')

            if not (name and email and mobile and password):
                flash("Please fill all required fields", "danger")
                return redirect(url_for('customer_signup'))

            if Customer.query.filter_by(email=email).first():
                flash("Email already exists", "danger")
                return redirect(url_for('customer_signup'))

            # Generate OTP
            otp = str(random.randint(100000, 999999))

            # Store temporarily
            session['customer_signup_data'] = {
                "name": name,
                "email": email,
                "mobile": mobile,
                "address": address,
                "password_hash": generate_password_hash(password),
            }
            session['customer_otp'] = otp

            # Send OTP via SendGrid
            send_email_otp(email, otp)

            flash("OTP sent to your email!", "success")
            return redirect(url_for("customer_verify_otp"))

        return render_template("customer_signup.html")

    
    @app.route('/customer/verify-otp', methods=['GET', 'POST'])
    def customer_verify_otp():
        data = session.get('customer_signup_data')

        if not data:
            flash("Session expired. Please sign up again.", "danger")
            return redirect(url_for('customer_signup'))

        if request.method == 'POST':
            user_otp = request.form.get('otp')
            real_otp = session.get('customer_otp')

            if user_otp != real_otp:
                flash("Incorrect OTP! Please try again.", "danger")
                return redirect(url_for('customer_verify_otp'))

            # Create customer
            cuid = generate_cuid()
            new_customer = Customer(
                name=data["name"],
                email=data["email"],
                mobile=data["mobile"],
                address=data["address"],
                password_hash=data["password_hash"],
                cuid=cuid
            )

            db.session.add(new_customer)
            db.session.commit()

            # Cleanup
            session.pop("customer_signup_data")
            session.pop("customer_otp")

            flash(f"Signup successful! Your CUID: {cuid}", "success")
            return redirect(url_for("customer_login"))

        return render_template("customer_verify_otp.html")

    
    @app.route('/customer/resend-otp')
    def customer_resend_otp():
        data = session.get('customer_signup_data')

        if not data:
            flash("Session expired. Please sign up again.", "danger")
            return redirect(url_for('customer_signup'))

        new_otp = str(random.randint(100000, 999999))
        session['customer_otp'] = new_otp

        # Send OTP again via SendGrid
        send_email_otp(data["email"], new_otp)

        flash("A new OTP has been sent!", "success")
        return redirect(url_for('customer_verify_otp'))





    @app.route('/customer/login', methods=['GET','POST'])
    def customer_login():
        key_id = "customer_login"

        # If rate-limited / blocked
        if not check_rate_limit(key_id):
            flash("Too many failed login attempts! Try again after 5 minutes.", "danger")
            return render_template('customer_login.html')  # <-- NO redirect

        if request.method == 'POST':
            identifier = request.form.get('identifier')
            password = request.form.get('password')

            cust = Customer.query.filter(
                (Customer.email == identifier) | (Customer.cuid == identifier)
            ).first()

            if cust and check_password_hash(cust.password_hash, password):
                # Reset attempts on success
                attempts[key_id] = {"count": 0, "block_until": None}

                session.clear()
                session['role'] = 'customer'
                session['customer_id'] = cust.id
                session['customer_name'] = cust.name
                flash("Customer logged in", "success")
                return redirect(url_for('customer_dashboard'))

            # Failed login
            record_failed_attempt(key_id)
            flash("Invalid credentials!", "danger")

            return render_template('customer_login.html')  # <-- NO redirect

        return render_template('customer_login.html')


    @app.route('/customer/logout')
    def customer_logout():
        session.clear()
        flash("Logged out", "info")
        return redirect(url_for('home'))

    @app.route('/customer/dashboard', methods=['GET','POST'])
    @customer_required
    def customer_dashboard():
        customer = Customer.query.get(session['customer_id'])
        if request.method == 'POST':
            # placing order: either raw_text or file
            raw_text = request.form.get('order_text')
            pickup = request.form.get('pickup_option') or 'Self Pick'
            f = request.files.get('order_file')
            filename = None
            if f and allowed_file(f.filename):
                filename = secure_filename(f.filename)
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            if (not raw_text) and (not filename):
                flash("Enter items or upload file", "danger")
                return redirect(url_for('customer_dashboard'))
            order_id = generate_order_id()
            order = Order(order_id=order_id, customer_id=customer.id,
                          raw_text=raw_text, uploaded_filename=filename, pickup_option=pickup)
            db.session.add(order)
            db.session.commit()
            flash(f"Order placed. Order ID: {order_id}", "success")
            return redirect(url_for('customer_dashboard'))
        # GET
        orders = Order.query.filter_by(customer_id=customer.id).order_by(Order.created_at.desc()).all()
        # find bill if exists for each order
        bills = {}
        for o in orders:
            b = Bill.query.filter_by(order_id=o.order_id).first()
            if b:
                bills[o.order_id] = b
        return render_template('customer_dashboard.html', customer=customer, orders=orders, bills=bills)

    @app.route('/customer/update', methods=['GET', 'POST'])
    @customer_required
    def customer_update():
        customer = Customer.query.get(session['customer_id'])

        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            mobile = request.form.get('mobile')
            address = request.form.get('address')

            # Check if email already exists
            existing = Customer.query.filter_by(email=email).first()
            if existing and existing.id != customer.id:
                flash("Email already taken", "danger")
                return redirect(url_for('customer_update'))

            customer.name = name
            customer.email = email
            customer.mobile = mobile
            customer.address = address

            db.session.commit()
            session['customer_name'] = name
            flash("Profile updated successfully", "success")
            return redirect(url_for('customer_dashboard'))

        return render_template('customer_update.html', customer=customer)

    @app.route('/customer/delete', methods=['POST'])
    @customer_required
    def customer_delete():
        customer = Customer.query.get(session['customer_id'])

        # Delete all customer orders
        orders = Order.query.filter_by(customer_id=customer.id).all()
        for o in orders:
            if o.uploaded_filename:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], o.uploaded_filename))
                except:
                    pass
            db.session.delete(o)

        db.session.delete(customer)
        db.session.commit()

        session.clear()
        flash("Your account has been permanently deleted.", "info")
        return redirect(url_for('home'))

    @app.route("/customer/forgot-password", methods=["GET", "POST"])
    def customer_forgot_password():
        if request.method == "POST":
            email = request.form["email"]
            new_password = request.form["new_password"]
            confirm_password = request.form["confirm_password"]

            if new_password != confirm_password:
                flash("Passwords do not match!", "error")
                return redirect(url_for("customer_forgot_password"))

            customer = Customer.query.filter_by(email=email).first()
            if not customer:
                flash("Email not registered!", "error")
                return redirect(url_for("customer_forgot_password"))

            customer.password_hash = generate_password_hash(new_password)  # FIXED
            db.session.commit()

            flash("Password updated successfully!", "success")
            return redirect(url_for("customer_login"))

        return render_template("customer_forgot_password.html")



    @app.route('/customer/order/<int:order_pk>/delete', methods=['POST'])
    @customer_required
    def customer_delete_order(order_pk):
        customer = Customer.query.get(session['customer_id'])
        order = Order.query.get_or_404(order_pk)
        if order.customer_id != customer.id:
            abort(403)
        if order.uploaded_filename:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], order.uploaded_filename))
            except:
                pass
        db.session.delete(order)
        db.session.commit()
        flash("Order deleted", "info")
        return redirect(url_for('customer_dashboard'))

    # view bill download
    @app.route('/bill/download/<bill_id>')
    def download_bill(bill_id):
        bill = Bill.query.filter_by(bill_id=bill_id).first_or_404()
        if not bill.pdf_filename:
            abort(404)
        return send_from_directory(app.config['UPLOAD_FOLDER'], bill.pdf_filename, as_attachment=True)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)