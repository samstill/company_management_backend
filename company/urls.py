# company/urls.py

from django.urls import path
from .views import CompanyListCreateView, DepartmentListCreateView, DepartmentEmployeeListCreateView

urlpatterns = [
    path('companies/', CompanyListCreateView.as_view(), name='company-list-create'),
    path('companies/<int:company_id>/departments/', DepartmentListCreateView.as_view(), name='department-list-create'),
    path('departments/<int:department_id>/employees/', DepartmentEmployeeListCreateView.as_view(), name='department-employee-list-create'),
]
