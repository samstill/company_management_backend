# Company Management Backend

Django REST API for company administration, employee management, account-based access, and hotel booking workflows.

## Tech stack
- Python 3
- Django 5.1.1
- Django REST Framework
- Simple JWT
- SQLite

## Project apps
- `accounts`: custom email-based user model, role management, registration, JWT login, and admin-only access.
- `company`: company, department, and department-employee assignment management.
- `employee`: employee profiles and performance review records.
- `hotel`: room search, bookings, reviews, payments, and coupon-based pricing.

## API base paths
- `/api/accounts/`
- `/api/company/`
- `/api/employee/`
- `/api/hotel/`

## Main endpoints
### Accounts
- `POST /api/accounts/register/` — register a user.
- `POST /api/accounts/login/` — obtain JWT tokens.
- `POST /api/accounts/token/refresh/` — refresh an access token.
- `GET /api/accounts/admin-only/` — admin-only sample endpoint.
- `GET /api/accounts/verify-email/<uidb64>/<token>/` — verify email links.

### Company
- `GET, POST /api/company/companies/` — list or create companies.
- `GET, POST /api/company/companies/<company_id>/departments/` — list or create departments for a company.
- `GET, POST /api/company/departments/<department_id>/employees/` — list or assign department employees.

### Employee
- `GET, POST /api/employee/employees/` — list or create employees.
- `GET, PUT, PATCH, DELETE /api/employee/employees/<id>/` — manage a single employee.
- `GET, POST /api/employee/employees/<employee_id>/performances/` — manage employee performance reviews.

### Hotel
- `GET /api/hotel/rooms/` — search available rooms with optional `room_type`, `check_in_date`, and `check_out_date` query params.
- `POST /api/hotel/bookings/` — create a booking for the authenticated user.
- `GET /api/hotel/bookings/history/` — view booking history.
- `PUT, PATCH /api/hotel/bookings/cancel/<id>/` — cancel a booking.
- `POST /api/hotel/reviews/` — create a room review.
- `POST /api/hotel/payments/` — create and complete a payment.

## Authentication and permissions
- The API uses JWT authentication through `rest_framework_simplejwt`.
- Most endpoints require authentication by default.
- The custom user model uses email instead of username.
- Supported roles: `admin`, `manager`, `executive_director`, `employee`, `customer`.

## Local setup
1. Create and activate a virtual environment.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Apply migrations:
   ```bash
   python manage.py migrate
   ```
4. Run the development server:
   ```bash
   python manage.py runserver
   ```

## Running tests
```bash
python manage.py test
```

Current repository test discovery reports no tests executed.
