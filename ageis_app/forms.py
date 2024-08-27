from django import forms
from ageis_app.models import *


class SkillForm(forms.ModelForm):
    class Meta:
        model = Skills
        fields = ['skill']

class QualificationForm(forms.ModelForm):
    class Meta:
        model = Qualification
        fields = ['degree', 'institution', 'completion_year']

class ExperienceForm(forms.ModelForm):
    class Meta:
        model = Experience
        fields = ['company', 'position', 'start_date', 'end_date', 'description']


class ClientAddForm(forms.ModelForm):
    class Meta:
        model = Clients
        fields = ['company_logo','company_name','address','company_email']
        exclude = ['added_by']
        widgets = {
            'company_logo' : forms.ClearableFileInput(attrs={'class':'form-control w-75'}),
            # 'company_logo' : forms.ClearableFileInput(attrs={'class':'form-control uploadProfileInput','id':'newProfilePhoto','accept':'image/*' ,'style':'opacity: 0;'}),
            'company_name' : forms.TextInput(attrs={'class':'form-control w-75' ,'placeholder':"Enter Company Name"}),
            'address' : forms.Textarea(attrs={'class':'form-control w-75','placeholder':'Enter the comapny address','rows':3}),
            'company_email': forms.EmailInput(attrs={'class': 'form-control w-75', 'placeholder': 'Enter Company Email'}),
        }

class TestimonialAddForm(forms.ModelForm):
    class Meta:
        model = Testimonials
        exclude = ['added_by']
        widgets = {
            'customer_name' : forms.TextInput(attrs={'class':'form-control w-75','placeholder':'Customer name','required':'required'}),
            'customer_img' : forms.ClearableFileInput(attrs={'class':'form-control w-75'}),
            # 'company_name' : forms.Select(attrs={'class':'form-control w-75','required':'required'}),
            'reviews' : forms.Textarea(attrs={'class':'form-control w-75','placeholder':'Enter the review','rows':3,'required':'required'})
        }
    company_name = forms.ModelChoiceField(queryset=Clients.objects.all(), empty_label="Select Company",widget=forms.Select(attrs={'class':'form-control w-75','required':'required'}))



class JobCategoryAddForm(forms.ModelForm):
    class Meta:
        model = JobCategories
        fields = '__all__'

        widgets = {
            'name' : forms.TextInput(attrs={'class':'form-control w-75','placeholder':'Job Categorie','required':'required'}),
        }

class JobTypeAddForm(forms.ModelForm):
    class Meta:
        model = JobType
        fields = '__all__'

        widgets = {
            'name' : forms.TextInput(attrs={'class':'form-control w-75','placeholder':'Job Categorie','required':'required'}),
        }


class CountryAddForm(forms.ModelForm):
    class Meta:
        model = Country
        fields = '__all__'

        widgets = {
            'name' : forms.TextInput(attrs={'class':'form-control w-75','placeholder':'Job Categorie','required':'required'}),
        }





class JobsAddForm(forms.ModelForm):
    class Meta:
        model = Jobs
        fields = ['job_title', 'company_name', 'country', 'state', 'district', 'job_category', 'job_type', 'end_date', 'job_des', 'skills', 'experience', 'salary', 'languages', 'website_link']

        widgets = {
            'job_title': forms.TextInput(attrs={'class':'form-control w-75','placeholder':"Enter Job Title",'required':'required'}),
            'company_name': forms.ModelChoiceField(
                queryset=Clients.objects.all(),
                empty_label="Select Company",
                widget=forms.Select(attrs={'class': 'form-control w-75'})),
            # 'company_logo': forms.Select(attrs={'class':'form-control w-75'}),
            # 'company_email': forms.EmailInput(attrs={'class':'form-control w-75','placeholder':"Enter Company E-mail",'required':'required'}),
            # 'country': forms.Select(attrs={'class':'form-control w-75','placeholder':"Enter Company Location"}),
            # 'state': forms.Select(attrs={'class':'form-control w-75'}),
            # 'district': forms.Select(attrs={'class':'form-control w-75'}),
            # 'job_category': forms.Select(attrs={'class':'form-control w-75'}),
            # 'job_type': forms.Select(attrs={'class':'form-control w-75'}),
            'end_date': forms.DateInput(attrs={'class':'form-control w-75','type':'date','placeholder':"Enter  END Date",'required':'required'}),
            'job_des': forms.Textarea(attrs={'class':'form-control w-75','rows':3,'placeholder':"Enter The Job Description",'required':'required'}),
            'skills': forms.TextInput(attrs={'class':'form-control w-75','placeholder':"Enter The Skills",'required':'required'}),
            'experience': forms.TextInput(attrs={'class':'form-control w-75', 'placeholder':"Enter The Experience",'required':'required'}),
            'salary': forms.TextInput(attrs={'class':'form-control w-75','placeholder':"Enter The Salary"}),
            'languages': forms.TextInput(attrs={'class':'form-control w-75','placeholder':"Enter The Language",'required':'required'}),
            'website_link': forms.URLInput(attrs={'class':'form-control w-75','placeholder':"Enter The Website Link",'required':'required'}),
        }
    company_name =  forms.ModelChoiceField(queryset=Clients.objects.all(), empty_label="Select Company",widget=forms.Select(attrs={'class':'form-control w-75','required':'required'}))
    country = forms.ModelChoiceField(queryset=Country.objects.all(),empty_label='Select Country',widget=forms.Select(attrs={'class':'form-control w-75','required':'required'}))
    state = forms.ModelChoiceField(queryset=State.objects.all(),empty_label='Select State',widget=forms.Select(attrs={'class':'form-control w-75','required':'required'}))
    district = forms.ModelChoiceField(queryset=district.objects.all(),empty_label='Select District',widget=forms.Select(attrs={'class':'form-control w-75','required':'required'}))
    job_category = forms.ModelChoiceField(queryset=JobCategories.objects.all(),empty_label='Select Job Categories',widget=forms.Select(attrs={'class':'form-control w-75','required':'required'}))
    job_type = forms.ModelChoiceField(queryset=JobType.objects.all(),empty_label='Select Job Type',widget=forms.Select(attrs={'class':'form-control w-75','required':'required'}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['state'].queryset = State.objects.none()
        self.fields['district'].queryset = district.objects.none()

        if 'country' in self.data:
            try:
                country_id = int(self.data.get('country'))
                self.fields['state'].queryset = State.objects.filter(country=country_id)
            except (ValueError, TypeError):
                pass
        elif self.instance.pk:
            self.fields['state'].queryset = self.instance.country.state_set.all()

        if 'state' in self.data:
            try:
                state_id = int(self.data.get('state'))
                self.fields['district'].queryset = district.objects.filter(state=state_id)
            except (ValueError, TypeError):
                pass
        elif self.instance.pk and self.instance.state:
            self.fields['district'].queryset = self.instance.state.district_set.all()






class AboutUsAddForm(forms.ModelForm):
    class Meta:
        model = AboutUs
        fields = '__all__'
        widgets = {
            'review' : forms.Textarea(attrs={'class':'form-control w-75','placeholder':'Enter the review','rows':3,'required':'required'})
        }
    company = forms.ModelChoiceField(queryset=Clients.objects.all(), empty_label="Select Company",widget=forms.Select(attrs={'class':'form-control w-75','required':'required'}))

class SkillForm(forms.ModelForm):
    class Meta:
        model = Skills
        fields = ['skill']


class QualificationForm(forms.ModelForm):
    class Meta:
        model = Qualification
        fields = ['degree', 'institution', 'completion_year']

class ExperienceForm(forms.ModelForm):
    class Meta:
        model = Experience
        fields = ['company', 'position', 'start_date', 'end_date', 'description']

class ExtendedUserModelForm(forms.ModelForm):
    class Meta:
        model = ExtendedUserModel
        fields = ['location', 'position', 'comapany_univercity', 'profile_photo']