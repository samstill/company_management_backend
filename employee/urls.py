from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import EmployeeViewSet, EmployeePerformanceViewSet

router = DefaultRouter()
router.register(r'employees', EmployeeViewSet, basename='employee')
router.register(r'employees/(?P<employee_id>\d+)/performances', EmployeePerformanceViewSet, basename='employee-performance')

urlpatterns = [
    path('', include(router.urls)),
]
