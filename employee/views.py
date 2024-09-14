# employee/views.py

from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from .models import Employee, EmployeePerformance
from .serializers import EmployeeSerializer, EmployeePerformanceSerializer

class EmployeeListView(generics.ListCreateAPIView):
    queryset = Employee.objects.all()
    serializer_class = EmployeeSerializer
    permission_classes = [IsAuthenticated]


class EmployeeDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Employee.objects.all()
    serializer_class = EmployeeSerializer
    permission_classes = [IsAuthenticated]


class EmployeePerformanceListView(generics.ListCreateAPIView):
    queryset = EmployeePerformance.objects.all()
    serializer_class = EmployeePerformanceSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        employee_id = self.kwargs['employee_id']
        return EmployeePerformance.objects.filter(employee_id=employee_id)
