import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db, Admin, Customer, Order, Bill
from utils import generate_auid, generate_cuid, generate_order_id, generate_bill_id, now_str, items_to_json, items_from_json
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from PIL import Image
import json

UPLOAD_FOLDER = os.path.join('instance', 'uploads')
ALLOWED_EXT = set(['png','jpg','jpeg','gif','pdf','doc','docx'])

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'this-should-be-changed')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sri_vinayaga.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    db.init_app(app)

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

    # ----- Admin signup/login/dashboard -----
    @app.route('/admin/signup', methods=['GET','POST'])
    def admin_signup():
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            mobile = request.form.get('mobile')
            password = request.form.get('password')
            if not (name and email and mobile and password):
                flash("Please fill all fields", "danger")
                return redirect(url_for('admin_signup'))
            if Admin.query.filter_by(email=email).first():
                flash("Email already exists", "danger")
                return redirect(url_for('admin_signup'))
            auid = generate_auid()
            admin = Admin(name=name, email=email, mobile=mobile,
                          password_hash=generate_password_hash(password),
                          auid=auid)
            db.session.add(admin)
            db.session.commit()
            flash(f"Account created. Your AUID: {auid}", "success")
            return redirect(url_for('admin_login'))
        return render_template('admin_signup.html')

    @app.route('/admin/login', methods=['GET','POST'])
    def admin_login():
        if request.method == 'POST':
            identifier = request.form.get('identifier')  # email or AUID
            password = request.form.get('password')
            # try email then auid
            admin = Admin.query.filter((Admin.email==identifier) | (Admin.auid==identifier)).first()
            if admin and check_password_hash(admin.password_hash, password):
                session.clear()
                session['role'] = 'admin'
                session['admin_id'] = admin.id
                session['admin_name'] = admin.name
                flash("Admin logged in", "success")
                return redirect(url_for('admin_dashboard'))
            else:
                flash("Invalid credentials; if you don't have an account create one", "danger")
                return redirect(url_for('admin_login'))
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
    @app.route('/customer/signup', methods=['GET','POST'])
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
            cuid = generate_cuid()
            cust = Customer(name=name, email=email, mobile=mobile, address=address,
                            password_hash=generate_password_hash(password), cuid=cuid)
            db.session.add(cust)
            db.session.commit()
            flash(f"Account created. Your CUID: {cuid}", "success")
            return redirect(url_for('customer_login'))
        return render_template('customer_signup.html')

    @app.route('/customer/login', methods=['GET','POST'])
    def customer_login():
        if request.method == 'POST':
            identifier = request.form.get('identifier')  # email or CUID
            password = request.form.get('password')
            cust = Customer.query.filter((Customer.email==identifier) | (Customer.cuid==identifier)).first()
            if cust and check_password_hash(cust.password_hash, password):
                session.clear()
                session['role'] = 'customer'
                session['customer_id'] = cust.id
                session['customer_name'] = cust.name
                flash("Customer logged in", "success")
                return redirect(url_for('customer_dashboard'))
            else:
                flash("Invalid credentials; please sign up if you don't have an account", "danger")
                return redirect(url_for('customer_login'))
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
