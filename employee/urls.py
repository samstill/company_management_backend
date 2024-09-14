# employee/urls.py

from django.urls import path
from .views import EmployeeListView, EmployeeDetailView, EmployeePerformanceListView

urlpatterns = [
    path('employees/', EmployeeListView.as_view(), name='employee-list'),
    path('employees/<int:pk>/', EmployeeDetailView.as_view(), name='employee-detail'),
    path('employees/<int:employee_id>/performances/', EmployeePerformanceListView.as_view(), name='employee-performance-list'),
]
