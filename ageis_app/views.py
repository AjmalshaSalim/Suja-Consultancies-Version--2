from django.shortcuts import get_object_or_404, render,redirect
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect
from django.contrib.auth.models import User,auth
from django.contrib import messages
from ageis_app.models import *
from ageis_app.forms import *
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.db.models import Count
from django.views.generic import ListView
from django.db.models import F
from django.utils.crypto import get_random_string
from django.contrib.auth import authenticate, login
# Create your views here.

def index(request):
    recent_jobs = []
    whatsapp = None
    if request.user.is_authenticated:
        user = request.user
        recent_jobs = RecentlySearchedJobs.objects.filter(user=user).order_by('-search_date')

        extended_user_qs = ExtendedUserModel.objects.filter(user=user)
        if extended_user_qs.exists():
            print('extended_user_qs')
            extended_user = extended_user_qs.first()
                
                # Check the phone field
            if not extended_user.phone:
                    print('not extended_user.phone')
                    whatsapp = 'email'
        print('whatsapp',whatsapp)
    
    job_posted_count = Jobs.objects.all().count()
    applied_jobs_count = AppliedJobs.objects.all().count()
    company_count = Clients.objects.all().count()
    members_count = ExtendedUserModel.objects.all().count()
    companies = Clients.objects.all()
    jobs = Jobs.objects.all().order_by('job_post_date')[:4]
    job_category = JobCategories.objects.all()
    testimonial = Testimonials.objects.all()

    category_data = {}
    for category in job_category:
        category_data[category.id] = {
            'id': category.id,
            'name': category.name,
            'image_url': category.image.url if category.image else None,
            'count': Jobs.objects.filter(job_category=category).count()
        }
    print("category_data",category_data)
    # Count of jobs in specific categories
    development_count = Jobs.objects.filter(job_category__id=7).count()
    accounting_finance_count = Jobs.objects.filter(job_category__id=1).count()
    internship_count = Jobs.objects.filter(job_category__id=2).count()
    automotive_count = Jobs.objects.filter(job_category__id=3).count()
    marketing_count = Jobs.objects.filter(job_category__id=4).count()
    human_resource_count = Jobs.objects.filter(job_category__id=5).count()
    customer_service_count = Jobs.objects.filter(job_category__id=6).count()
    project_management_count = Jobs.objects.filter(job_category__id=8).count()
    design_count = Jobs.objects.filter(job_category__id=9).count()
    
    # Top 20 most-applied jobs
    most_applied_jobs = Jobs.objects.filter(application_count__gt=0).order_by('-application_count')[:20]

    
    context = {
        'companies': companies,
        'jobs': jobs,
        'job_posted_count': job_posted_count,
        'applied_jobs_count': applied_jobs_count,
        'company_count': company_count,
        'members_count': members_count,
        'testimonial': testimonial,
        'category_data': category_data,
        'development_count': development_count,
        'accounting_finance_count': accounting_finance_count,
        'internship_count': internship_count,
        'automotive_count': automotive_count,
        'marketing_count': marketing_count,
        'human_resource_count': human_resource_count,
        'customer_service_count': customer_service_count,
        'project_management_count': project_management_count,
        'design_count': design_count,
        'most_applied_jobs' :most_applied_jobs,
        'recent_jobs': recent_jobs,
        'whatsapp': whatsapp,
    }
    
    return render(request, 'index.html', context)


@login_required
def submit_whatsapp_number(request):
    if request.method == 'POST':
        whatsapp_number = request.POST.get('whatsapp_number')

        # Validate the number (you might want to add more robust validation)
        if whatsapp_number and whatsapp_number.isdigit() and len(whatsapp_number) == 10:
            # Get or create the user's profile
            user_profile, created = ExtendedUserModel.objects.get_or_create(user=request.user)

            # Save the WhatsApp number to the user's profile
            user_profile.phone = whatsapp_number
            user_profile.save()

            # Set a success message
            messages.success(request, 'Your WhatsApp number has been saved.')

            # Remove 'whatsapp' from session so the modal doesn't show again
            
        else:
            messages.error(request, 'Please enter a valid WhatsApp number.')

    return redirect('ageis_app:index')  # Redirect to the homepage after submission


def jobs_by_application_count(request):
    jobs = Jobs.objects.filter(application_count__gt=0).order_by('-application_count')
    return render(request, 'jobsfrontend.html', {'jobs': jobs})
    
@login_required
def recently_searched_jobs(request):
    user = request.user
    # Get the recently searched job objects
    recent_searches = RecentlySearchedJobs.objects.filter(user=user).order_by('-search_date')
    
    # Extract the jobs from the recent searches
    recent_jobs = [search.job for search in recent_searches]

 
    context = {
        'jobs': recent_jobs
    }
    return render(request, 'jobsfrontend.html', context)


def admin_registration(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        if password == password2:
            if User.objects.filter(username = username).exists():
                messages.error(request,'Username alredy exists')
                return redirect('ageis_app:admin_registration')
            elif User.objects.filter(email = email).exists():
                messages.error(request,'Email alredy exists')
                return redirect('ageis_app:admin_registration')
            else:
                User.objects.create_superuser(username=username,email=email,password=password)
                messages.success(request,'User created..')
                return redirect('ageis_app:login')
        else:
            messages.error(request,'Password Not Match')
            return redirect('ageis_app:admin_registration')
    return render(request,'admin-register.html')


def email_submission(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        
        # Check if the email is already registered (optional)

        # Generate OTP
        otp = get_random_string(length=6, allowed_chars='0123456789')
        
        # Save OTP to the session
        request.session['email'] = email
        request.session['otp'] = otp
        print("session email", request.session['email'])
        print("session otp", request.session['otp'])
        # Send OTP to the email
        send_mail(
            'Your OTP Code',
            f'Your OTP code is: {otp}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
        
        messages.success(request, 'OTP has been sent to your email.')
        return redirect('ageis_app:otp_verification')
    
    return render(request, 'email_login.html')


from django.contrib.auth import authenticate, login as auth_login

def otp_verification(request):
    if request.method == 'POST':
        email = request.session.get('email')
        otp_entered = request.POST.get('otp')
        
        # Get the OTP from the session
        otp_saved = request.session.get('otp')
        print('otp_entered',otp_entered)
        print('otp_saved',otp_saved)
        if otp_saved and otp_entered == otp_saved:
            # Check if the user already exists
            if User.objects.filter(email=email).exists():
                user = User.objects.get(email=email)
            else:
                # Create a new user if they do not exist
                username = email.split('@')[0]  # Simple username generation
                user = User.objects.create_user(username=username, email=email, password='12345678')
                extended_user = ExtendedUserModel.objects.create(user=user)
            # Authenticate using the email (or username) and the user's actual password
            
            user = authenticate(username=user.username, password='12345678')
            print(user)
            if user is not None:
                auth_login(request, user)  # Use auth_login to avoid the conflict
                messages.success(request, 'OTP verified and logged in successfully.')
                request.session.pop('email', None)
                request.session.pop('otp', None)
                return redirect('ageis_app:index')  # Redirect to home or another page

            else:
                messages.error(request, 'Authentication failed.')
        else:
            messages.error(request, 'Invalid OTP or OTP has expired.')
        return redirect('ageis_app:otp_verification')
    
    return render(request, 'otp_verification.html')



def resend_otp(request):
    email = request.session.get('email')
    
    if email:
        # Generate a new OTP
        otp = get_random_string(length=6, allowed_chars='0123456789')
        
        # Save the new OTP to the session
        request.session['otp'] = otp
        
        # Send the new OTP to the email
        send_mail(
            'Your New OTP Code',
            f'Your new OTP code is: {otp}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
        
        messages.success(request, 'A new OTP has been sent to your email.')
    else:
        messages.error(request, 'No email address found in session.')
    
    return redirect('ageis_app:otp_verification')



def user_registration(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        cv = request.FILES.get('resume')
        # print('CV',cv)
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        if password == password2:
            if User.objects.filter(username = username).exists():
                messages.error(request,'Username alredy exists')
                return redirect('ageis_app:user_registration')
            elif User.objects.filter(email = email).exists():
                messages.error(request,'Email alredy exists')
                return redirect('ageis_app:user_registration')
            else:
                user = User.objects.create_user(username=username,first_name=first_name,last_name=last_name,email=email,password=password)
                extendeduser = ExtendedUserModel(user = user, phone = phone, cv = cv)
                extendeduser.save()
                messages.success(request,'User created..')
                return redirect('ageis_app:login')
        else:
            messages.error(request,'Password Not Match')
            return redirect('ageis_app:user_registration')
    return render(request,'user-register.html')

def edit_user(request, user_id):
    if request.method == 'POST':

        print('Form Data:', request.POST)
        print('Degrees:', request.POST.getlist('degree[]'))
        print('Institutions:', request.POST.getlist('institution[]'))
        print('Completion Years:', request.POST.getlist('completion_year[]'))
      



        user = get_object_or_404(User, id=user_id)
        extended_user = get_object_or_404(ExtendedUserModel, user=user)
        
        # Update User fields
        user.first_name = request.POST.get('first_name')
        user.last_name = request.POST.get('last_name')
        user.email = request.POST.get('email')
        user.save()
        # Update ExtendedUserModel fields
        extended_user.phone = request.POST.get('phone')
        extended_user.location = request.POST.get('location')
        # Handle the CV upload
        if 'cv' in request.FILES:
            extended_user.cv = request.FILES['cv']
        extended_user.save()
        
        # Update Skills
        skills = request.POST.get('skills', '')
        skills_list = [skill.strip() for skill in skills.split(',') if skill.strip()]
        for skill in skills_list:
            Skills.objects.create(user=extended_user, skill=skill)


        # Update Qualifications
        degrees = request.POST.getlist('degree[]')
        institutions = request.POST.getlist('institution[]')
        completion_years = request.POST.getlist('completion_year[]')
        print("degrees",degrees,"institutions",institutions,"completion_years",completion_years)
        processed_qualification_ids = []

        for degree, institution, year in zip(degrees, institutions, completion_years):
            if degree and institution and year:
                qualification, created = Qualification.objects.update_or_create(
                    user=extended_user,
                    degree=degree,
                    institution=institution,
                    defaults={'completion_year': int(year)}
                )
                processed_qualification_ids.append(qualification.id)


        # Process Experiences
        companies = request.POST.getlist('company[]')
        positions = request.POST.getlist('position[]')
        start_dates = request.POST.getlist('start_date[]')
        end_dates = request.POST.getlist('end_date[]')
        descriptions = request.POST.getlist('description[]')

        print("companies",companies)
        # Track processed experience IDs to avoid duplications
        processed_experience_ids = []

        for company, position, start_date, end_date, description in zip(companies, positions, start_dates, end_dates, descriptions):
            if company and position and start_date:
                # Use a more specific filter to ensure uniqueness
                experience = Experience.objects.filter(
                    user=extended_user,
                    company=company,
                    position=position,
                    start_date=start_date
                ).first()
                
                if experience:
                    # Update the existing experience
                    experience.end_date = end_date if end_date else None
                    experience.description = description
                    experience.save()
                else:
                    # Create a new experience
                    Experience.objects.create(
                        user=extended_user,
                        company=company,
                        position=position,
                        start_date=start_date,
                        end_date=end_date if end_date else None,
                        description=description
                    )

        # Optionally, delete experiences that were not processed
        # Experience.objects.filter(user=extended_user).exclude(id__in=processed_experience_ids).delete()
        messages.success(request, 'User information updated successfully.')
        return redirect('ageis_app:user_management')
    
    return redirect('/')
    
    return HttpResponseRedirect('/')
def create_user(request):
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        location = request.POST.get('location')
        cv = request.FILES.get('cv')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists.')
            return redirect('ageis_app:create_user')

        username = email.split('@')[0]
        user = User.objects.create_user(username=username, first_name=first_name, last_name=last_name, email=email)
        extended_user = ExtendedUserModel(user=user, phone=phone, location=location, cv=cv)
        extended_user.save()

        # Handle Skills
        skills = request.POST.get('skills', '')
        skills_list = [skill.strip() for skill in skills.split(',') if skill.strip()]
        for skill in skills_list:
            Skills.objects.create(user=extended_user, skill=skill)

        # Handle Qualifications
        degrees = request.POST.getlist('degree[]')
        institutions = request.POST.getlist('institution[]')
        completion_years = request.POST.getlist('completion_year[]')
        for degree, institution, year in zip(degrees, institutions, completion_years):
            if degree and institution and year:
                Qualification.objects.create(
                    user=extended_user,
                    degree=degree,
                    institution=institution,
                    completion_year=int(year)
                )

        # Handle Experience
        companies = request.POST.getlist('company[]')
        positions = request.POST.getlist('position[]')
        start_dates = request.POST.getlist('start_date[]')
        end_dates = request.POST.getlist('end_date[]')
        descriptions = request.POST.getlist('description[]')
        for company, position, start_date, end_date, description in zip(companies, positions, start_dates, end_dates, descriptions):
            if company and position and start_date:
                Experience.objects.create(
                    user=extended_user,
                    company=company,
                    position=position,
                    start_date=start_date,
                    end_date=end_date if end_date else None,
                    description=description
                )

        messages.success(request, 'User created successfully.')
        return redirect('ageis_app:user_management')  # Replace with your actual user list view

    return redirect('/')  # Handle non-POST requests appropriately

    return render(request, 'create_user.html')
def login(request):
    if 'username' in  request.session:
        print("username in session already")
        return redirect('ageis_app:dashboard')

    if request.method == 'POST':
        username_or_email = request.POST.get('username_or_email')
        password = request.POST.get('password')
        user = auth.authenticate(request, username=username_or_email, password=password)
        if user is not None:
            print("Request is Post and user is not none")
            auth.login(request, user)
            request.session['username'] = username_or_email
            if user.is_superuser:
                return redirect('ageis_app:dashboard')
            else:
                print('User')
                return redirect('ageis_app:dashboard')
        else:
            print("Request is Post and user None")
            messages.error(request, 'Invalid credential..')
            return redirect('ageis_app:adminlogin')
    return render(request, 'login.html')


def logout(request):
    if 'username' in request.session:
        request.session.flush()
        print(request.session)
    return redirect('ageis_app:index')

from django.contrib.auth import logout as auth_logout
def user_logout(request):
    # Use Django's built-in logout function to log the user out
    auth_logout(request)
    return redirect('ageis_app:index')

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.urls import reverse
from django.core.mail import send_mail
from django.conf import settings

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        if ExtendedUserModel.objects.filter(user__email=email).exists():
            user = ExtendedUserModel.objects.get(user__email=email)
            user = User.objects.get(email=email)
            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            reset_link = request.build_absolute_uri(
                reverse('ageis_app:reset_password', kwargs={'uidb64': uidb64, 'token': token}))
            send_mail(
                'Password Reset Link',
                f'Please click on this link to reset your password: {reset_link}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )
            messages.success(request, 'Password reset link has been sent to your email.')
        else:
            messages.error(request, 'Email does not exist.')
    return render(request,'forgot-password.html')



def reset_password(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and PasswordResetTokenGenerator().check_token(user, token):
        if request.method == 'POST':
            if request.POST.get('password') == request.POST.get('password2'):
                password = request.POST.get('password')
                print(password)
                user.set_password(password)
                user.save()
                messages.success(request, 'Password has been reset.')
                return redirect('ageis_app:login')
            else:
                messages.error(request,'Password not matching')
                print('password not matching')
                reset_password_url = reverse('ageis_app:reset_password', args=[uid, token])
                return redirect(reset_password_url)
        else:
            
            return render(request, 'reset-password.html')
    else:
        messages.error(request, 'Invalid reset link.')
        return redirect('ageis_app:login')






@login_required(login_url='ageis_app:adminlogin')
def dashboard(request):
    if request.user.is_superuser:
        testimonial_count = Testimonials.objects.all().count()
        client_count = Clients.objects.all().count()
        jobs_count = Jobs.objects.all().count()
        applied_jobs_count = AppliedJobs.objects.all().count()
        context = {
            'testimonial_count':testimonial_count,
            'client_count' :client_count,
            'jobs_count':jobs_count,
            'applied_jobs_count' :applied_jobs_count
        }
        return render(request,'dashboard.html',context)
    else:
        return HttpResponse('Access Denied..')


@login_required(login_url='ageis_app:login')
def testimonial(request):
    if request.method == 'POST':
        form = TestimonialAddForm(request.POST,request.FILES)
        if form.is_valid():
            data = form.save(commit=False)
            data.added_by = request.user
            data.save()
            messages.success(request,'Added..')
            return redirect('ageis_app:testimonial')
    else:
        form = TestimonialAddForm()
    
    testimonial = Testimonials.objects.all()
    context = {
        'form':form,
        'testimonial':testimonial
    }
    return render(request,'testimonal.html',context)

@login_required(login_url='ageis_app:login')
def testimonial_edit(request,update_id):
    update = Testimonials.objects.filter(id=update_id).first()
    if request.method == 'POST':
        form = TestimonialAddForm(request.POST,request.FILES,instance=update)
        if form.is_valid():
            form.save()
            messages.success(request,'Updated..')
            return redirect('ageis_app:testimonial')
    else:
        form = TestimonialAddForm(instance=update)

    context ={
        'form':form
    }
    return render(request,'testimonial-edit.html',context)


@login_required(login_url='ageis_app:login')
def testimonial_delete(request,delete_id):
    delete_id = Testimonials.objects.filter(id=delete_id)
    delete_id.delete()
    messages.success(request,'Deleted..')
    return redirect('ageis_app:testimonial')


@login_required(login_url='ageis_app:login')
def client(request):
    if request.method == 'POST':
        form = ClientAddForm(request.POST,request.FILES)
        if form.is_valid():
            # logo = form.cleaned_data['company_logo']
            data = form.save(commit=False)
            data.added_by = request.user
            # data.company_logo = logo
            data.save()
            messages.success(request,'Added..')
            return redirect('ageis_app:client')
    else:
        form = ClientAddForm()

    clients = Clients.objects.all()
    return render(request,'client.html',{'form':form,'clients':clients})



@login_required(login_url='ageis_app:login')
def client_edit(request,client_id):
    form = ClientAddForm()
    update = Clients.objects.filter(id=client_id).first()
    if request.method == 'POST':
        form = ClientAddForm(request.POST,request.FILES,instance=update)
        if form.is_valid():
            messages.success(request,'Updated..')
            form.save()
            return redirect('ageis_app:client')
    else:
        form = ClientAddForm(instance=update)
    context = {
        'form' : form
    }
    return render(request,'editclient.html',context)


@login_required(login_url='ageis_app:login')
def client_delete(request,client_id):
    clients = Clients.objects.get(id=client_id)
    clients.delete()
    messages.success(request,'Deleted..')
    return redirect('ageis_app:client')


@login_required(login_url='ageis_app:login')
def job_categories(request):
    if request.method == 'POST':
        form = JobCategoryAddForm(request.POST, request.FILES)  # Include request.FILES for file uploads
        if form.is_valid():
            form.save()
            messages.success(request, 'Added..')
            return redirect('ageis_app:job_categories')
    else:
        form = JobCategoryAddForm()

    categories = JobCategories.objects.all()
    context = {
        'form': form,
        'categories': categories
    }
    return render(request, 'jobcategories.html', context)


@login_required(login_url='ageis_app:login')
def job_categories_edit(request, update_id):
    # Retrieve the job category object by id
    update = JobCategories.objects.filter(id=update_id).first()

    if not update:
        # Handle the case where the job category is not found
        messages.error(request, 'Job category not found.')
        return redirect('ageis_app:job_categories')

    if request.method == 'POST':
        # Include request.FILES to handle file uploads
        form = JobCategoryAddForm(request.POST, request.FILES, instance=update)
        if form.is_valid():
            form.save()
            messages.success(request, 'Updated successfully.')
            return redirect('ageis_app:job_categories')
    else:
        form = JobCategoryAddForm(instance=update)

    context = {
        'form': form,
    }
    return render(request, 'jobcategories-edit.html', context)



@login_required(login_url='ageis_app:login')
def job_categorie_delete(request,delete_id):
    categorie = JobCategories.objects.filter(id=delete_id).first()
    categorie.delete()
    messages.success(request,'Deleted..')
    return redirect('ageis_app:job_categories')


@login_required(login_url='ageis_app:login')
def job_types(request):
    if request.method == 'POST':
        form = JobTypeAddForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request,'Added..')
            return redirect('ageis_app:job_types')
    else:
        form = JobTypeAddForm()

    jobtypes = JobType.objects.all()
    context = {
        'form':form,
        'jobtypes':jobtypes
    }
    return render(request,'jobtypes.html',context)


@login_required(login_url='ageis_app:login')
def job_type_edit(request,update_id):
    update = JobType.objects.filter(id = update_id).first()
    if request.method == 'POST':
        form = JobTypeAddForm(request.POST,instance=update)
        if form.is_valid():
            form.save()
            messages.success(request,'Updated..')
            return redirect('ageis_app:job_types')
    else:
        form = JobTypeAddForm(instance=update)
    context = {
        'form':form,
    }
    return render(request,'jobcategories-edit.html',context)




@login_required(login_url='ageis_app:login')
def job_type_delete(request,delete_id):
    categorie = JobType.objects.filter(id=delete_id).first()
    categorie.delete()
    messages.success(request,'Deleted..')
    return redirect('ageis_app:job_types')



@login_required(login_url='ageis_app:login')
def load_states(request):
    country_id = request.GET.get('country_id')
    states = State.objects.filter(country=country_id).all()
    return render(request, 'city_dropdown_list_options.html', {'states': states})


@login_required(login_url='ageis_app:login')
def load_district(request):
    country_id = request.GET.get('country_id')
    districts = district.objects.filter(state=country_id).all()
    return render(request, 'place_dropdown_list_options.html', {'districts': districts})







@login_required(login_url='ageis_app:login')
def jobs(request):
    try:
        if request.method == 'POST':
            form = JobsAddForm(request.POST)
            if form.is_valid():
                data = form.cleaned_data
                company = data.get('company_name')
                print("Company is :",company)
                # Ensure 'company' is not None before saving
                if company is not None:
                    job = form.save(commit=False)
                    job.added_by = request.user
                    job.company = company
                    job.save()
                    messages.success(request, 'Job added successfully.')
                    return redirect('ageis_app:jobs')
                else:
                    messages.error(request, 'Invalid company selected.')
            else:
                print(form.errors)
                messages.error(request, 'Error in the form submission. Please check the form data.')
        else:
            form = JobsAddForm()
    except Exception as e:
        messages.error(request, str(e))
        return redirect('ageis_app:jobs')
 
    jobs = Jobs.objects.all()
    context = {
        'form': form,
        'jobs': jobs,
    }
    return render(request, 'jobs.html', context)

@login_required(login_url='ageis_app:login')
def jobs_edit(request,update_id):
    update = Jobs.objects.filter(id=update_id).first()
    if request.method == 'POST':
        form = JobsAddForm(request.POST,request.FILES,instance=update)
        if form.is_valid():
            form.save()
            messages.success(request,'Updated..')
            return redirect('ageis_app:jobs')
    else:
        form = JobsAddForm(instance=update)
    context = {
        'form':form
    }
    return render(request,'jobs-edit.html',context)



@login_required(login_url='ageis_app:login')
def job_delete(request,delete_id):
    jobs = Jobs.objects.get(id = delete_id)
    jobs.delete()
    messages.success(request,'Deleted....')
    return redirect('ageis_app:jobs')



@login_required(login_url='ageis_app:login')
def place_management(request):
    country = Country.objects.all()
    state = State.objects.all()
    district_list = district.objects.all()
    return render(request,'place-management.html',{'country':country,'state':state,'state':state,'district_list':district_list})



@login_required(login_url='ageis_app:login')
def country_add(request):
    if request.method == 'POST':
        Country.objects.create(name=request.POST.get('country')).save()
        messages.success(request,'Succesfully Added')
    return redirect('ageis_app:place_management')




@login_required(login_url='ageis_app:login')
def country_update(request,country_id):
    updte = Country.objects.filter(id = country_id).first()
    if request.method == 'POST':
        updte.name = request.POST.get('name')
        updte.save()
        messages.success(request,'Updated..')
        return redirect('ageis_app:place_management')
    return render(request,'edit-country.html',{'updte':updte})


@login_required(login_url='ageis_app:login')
def country_delete(request,country_id):
    dlt = Country.objects.filter(id=country_id)
    dlt.delete()
    messages.success(request,'Deleted..')
    return redirect('ageis_app:place_management')


@login_required(login_url='ageis_app:login')
def state_add(request):
    if request.method == 'POST':
        country = request.POST.get('country')
        country = Country.objects.get(name= country)
        State.objects.create(country = country,name=request.POST.get('state')).save()
        messages.success(request,'Succesfully Added')
    return redirect('ageis_app:place_management')



@login_required(login_url='ageis_app:login')
def state_update(request,state_id):
    country = Country.objects.all()
    updte = State.objects.filter(id = state_id).first()
    if request.method == 'POST':
        country_name = request.POST.get('country')
        country = Country.objects.get(name=country_name)
        updte.name = request.POST.get('name')
        updte.country = country
        updte.save()
        messages.success(request,'Updated..')
        return redirect('ageis_app:place_management')
    return render(request,'edit-state.html',{'updte':updte,'country':country})




@login_required(login_url='ageis_app:login')
def state_delete(request,state_id):
    dlt = State.objects.filter(id=state_id)
    dlt.delete()
    messages.success(request,'Deleted..')
    return redirect('ageis_app:place_management')


@login_required(login_url='ageis_app:login')
def district_add(request):
    if request.method == 'POST':
        state_name = request.POST.get('state')
        state = State.objects.filter(name= state_name).first()
        district.objects.create(state = state,name=request.POST.get('district')).save()
        messages.success(request,'Succesfully Added')
    return redirect('ageis_app:place_management')



@login_required(login_url='ageis_app:login')
def district_update(request,district_id):
    state = State.objects.all()
    updte = district.objects.filter(id = district_id).first()
    if request.method == 'POST':
        state_name = request.POST.get('country')
        states = State.objects.filter(name=state_name).first()
        updte.name = request.POST.get('name')
        updte.state = states
        updte.save()
        messages.success(request,'Updated..')
        return redirect('ageis_app:place_management')
    return render(request,'edit-state.html',{'updte':updte,'country':state})   # here state edit and disrtict edits are used both same templates




@login_required(login_url='ageis_app:login')
def district_delete(request,district_id):
    dlt = district.objects.filter(id=district_id).first()
    dlt.delete()
    messages.success(request,'Deleted..')
    return redirect('ageis_app:place_management')

from django .core.paginator import Paginator, EmptyPage , PageNotAnInteger

def jobs_frontend(request):

    all_jobs = Jobs.objects.all()
    per_page = 8
    paginator = Paginator(all_jobs,per_page)
    page= request.GET.get('page')
    try:
        jobs = paginator.page(page)
    except PageNotAnInteger:
        jobs = paginator.page(1)
    except EmptyPage:
        jobs=paginator.page(Paginator.num_pages)
    context = {
        'jobs':jobs
    }
    return render(request,'jobsfrontend.html',context)


def jobs_frontend_cat(request, cat_id=None):
    if cat_id :
          jobs = Jobs.objects.filter(job_category__id = cat_id)
    else:
         jobs = Jobs.objects.all()
    context = {
        'jobs':jobs
    }
    return render(request,'jobsfrontend.html',context)

@login_required(login_url='ageis_app:login')
def jobs_details(request, job_id):
    job = get_object_or_404(Jobs, id=job_id)
    applied = AppliedJobs.objects.filter(applied_user=request.user.extenedusermodel, applied_job=job).exists()

    return render(request, 'job-details.html', {'details': job, 'applied': applied})

# product list page, product view page


@login_required(login_url='ageis_app:login')
def user_management(request):
    userlist = ExtendedUserModel.objects.all().order_by('-id')
    return render(request,'user-management.html',{'userlist':userlist})


@login_required(login_url='ageis_app:login')
def apply_job(request,job_id):
    first_name = request.user.first_name
    last_name = request.user.last_name
    full_name = first_name+' '+last_name

    jobs = Jobs.objects.get(id=job_id)
    if jobs.application_count is None:
        jobs.application_count = 0
        
        # Increment the application_count by 1
    jobs.application_count = F('application_count') + 1
    jobs.save()
    jobs.refresh_from_db()


    user = ExtendedUserModel.objects.get(user = request.user)
    AppliedJobs.objects.create(
        applied_user = user,
        applied_job = jobs

    ).save()
    # Leads.objects.create(name = full_name,
    #                      title = jobs.job_title,
    #                      company = jobs.company.company_name,
    #                      description = jobs.job_des,
    #                      country = jobs.country.id,
    #                      city = jobs.district.name,
    #                      state = jobs.state.name,
    #                      address = jobs.company.address,
    #                      email = request.user.email,
    #                      website = jobs.website_link ,
    #                      phonenumber = request.user.extenedusermodel.phone,
    #                      ).save()
    messages.success(request,'Job Applied..')
    return redirect('ageis_app:jobs_frontend')


def applied_jobs(request):
    applied_jobs = AppliedJobs.objects.all()
    return render(request,'applied-jobs-lists.html',{'applied_jobs':applied_jobs})

def shortlist_candidate(request, job_id):
    applied_job = get_object_or_404(AppliedJobs, id=job_id)
    applied_job.is_shortlisted = True
    applied_job.save()

    # Get the candidate's email address from the User model
    candidate_email = applied_job.applied_user.user.email
    print (request.user.username)
    # Retrieve the details of the job
    job = applied_job.applied_job
    job_title = job.job_title
    job_company = job.company.company_name  # Assuming 'company_name' is the attribute for the company name
    job_description = job.job_des

    # Compose the email
    email_subject = 'Congratulations! You have been shortlisted for a job'
    email_body = (
        f'Dear candidate,\n\n'
        f'We are pleased to inform you that you have been shortlisted for the following job:\n\n'
        f'Job Title: {job_title}\n'
        f'Company: {job_company}\n'
        f'Description: {job_description}\n\n'
        f'Please contact us for further instructions.\n\n'
        f'Best regards,\n'
        f'The Recruitment Team'
    )

    # Send the email
    send_mail(
        email_subject,
        email_body,
        settings.EMAIL_HOST_USER,  # Sender's email address
        [candidate_email],  # Recipient's email address
        fail_silently=False,
    )

    return redirect('ageis_app:applied_jobs')
def schedule_interview(request):
    if request.method == 'POST':
        applied_job_id = request.POST.get('applied_job_id')
        applied_job = AppliedJobs.objects.get(pk=applied_job_id)
        candidate_email = applied_job.applied_user.user.email
        job = applied_job.applied_job

        # Retrieve the subject from the form
        subject = request.POST.get('subject')
        date = request.POST.get('date')
        time = request.POST.get('time')
        if not subject:
            subject = 'Interview Invitation'

        # Compose the email
        email_body = (
            f'Dear candidate,\n\n'
            f'We are pleased to invite you for an interview for the position of {job.job_title} '
            f'at {job.company.company_name}.\n\n'
            f'Your application stood out to us, and we would like to learn more about your qualifications.\n'
            f'Please find the details below:\n\n'
            f'Date: {date}\n'
            f'Time: {time}\n'
           f'\n\n{subject}\n\n'
            f'\n\nWe look forward to meeting you and discussing your potential role at {job.company.company_name}\n\n'
            f'Best regards,\n'
            f'The Recruitment Team'
        )

        # Send the email
        send_mail(
            subject,
            email_body,
            settings.EMAIL_HOST_USER,  # Sender's email address
            [candidate_email],  # Recipient's email address
            fail_silently=False,
        )

        # Update the is_invited field
        applied_job.is_invited = True
        applied_job.save()

        return redirect('ageis_app:shortlisted_jobs')
    else:
        # Handle GET request
        return redirect('ageis_app:shortlisted_jobs')
    

from django.core.mail import EmailMessage
import logging

logger = logging.getLogger(__name__)

def send_offer_letter(request):
    if request.method == 'POST':
        applied_job_id = request.POST.get('applied_job_id')
        logger.debug(f'Received applied_job_id: {applied_job_id}')
        if not applied_job_id:
            logger.error('Applied job ID is empty')
            return JsonResponse({'success': False, 'error': 'Applied job ID is empty'})

        try:
            applied_job_id = int(applied_job_id)
            applied_job = AppliedJobs.objects.get(pk=applied_job_id)
        except ValueError:
            logger.error(f'Invalid job ID: {applied_job_id}')
            return JsonResponse({'success': False, 'error': 'Invalid job ID'})
        except AppliedJobs.DoesNotExist:
            logger.error(f'Applied job does not exist: {applied_job_id}')
            return JsonResponse({'success': False, 'error': 'Applied job does not exist'})

        candidate_email = applied_job.applied_user.user.email
        logger.debug(f'Candidate email: {candidate_email}')

        offer_letter_file = request.FILES.get('offer_letter_file')
        email_subject = request.POST.get('email_subject')
        email_body = request.POST.get('email_body')

        if offer_letter_file:
            applied_job.offer_letter = offer_letter_file
            applied_job.save()

        email = EmailMessage(
            email_subject,
            email_body,
            settings.EMAIL_HOST_USER,
            [candidate_email],
            reply_to=[settings.EMAIL_HOST_USER]
        )
        if offer_letter_file:
            email.attach(offer_letter_file.name, offer_letter_file.read(), offer_letter_file.content_type)

        try:
            email.send(fail_silently=False)
        except Exception as e:
            logger.error(f'Error sending email: {e}')
            return JsonResponse({'success': False, 'error': str(e)})

        applied_job.result = 'offerletter_sent'
        applied_job.save()
        return JsonResponse({'success': True})

    logger.error('Invalid request method')
    return JsonResponse({'success': False, 'error': 'Invalid request method'})



from django.http import JsonResponse
def update_interview_result(request, job_id):
    applied_job = AppliedJobs.objects.get(pk=job_id)
    result = request.POST.get('result')  # Assuming 'result' is passed in the AJAX request
    if result == 'selected':
        applied_job.result = 'selected'
    elif result == 'rejected':
        applied_job.result = 'rejected'
    elif result == 'on_hold':
        applied_job.result = 'on_hold'
    applied_job.save()
    return JsonResponse({'status': 'success'})


def shortlisted_jobs(request):
    clients = Clients.objects.all()  # Retrieve all clients
    jobs = Jobs.objects.all()  # Retrieve all jobs

    # If a client is selected from the dropdown
    selected_client_id = request.GET.get('client')
    if selected_client_id:
        selected_client = get_object_or_404(Clients, pk=selected_client_id)
        jobs = jobs.filter(company=selected_client)
        applied_jobs = AppliedJobs.objects.filter(
            applied_job__company=selected_client,
            is_shortlisted=True
        )
    else:
        applied_jobs = AppliedJobs.objects.filter(is_shortlisted=True)

    # If a job is selected from the dropdown
    selected_job_id = request.GET.get('job')
    if selected_job_id:
        selected_job = get_object_or_404(Jobs, pk=selected_job_id)
        applied_jobs = applied_jobs.filter(applied_job=selected_job)

    return render(request, 'shortlisted_jobs.html', {
        'clients': clients,
        'jobs': jobs,
        'applied_jobs': applied_jobs,
        'selected_client_id': int(selected_client_id) if selected_client_id else None,
        'selected_job_id': int(selected_job_id) if selected_job_id else None,
    })
def remove_from_shortlist(request, job_id):

    applied_job = get_object_or_404(AppliedJobs, id=job_id)
    applied_job.is_shortlisted = False
    applied_job.save()

    return redirect('ageis_app:applied_jobs')

def filter_results(request):
    selected_result = request.GET.get('result')

    if selected_result:
        applied_jobs = AppliedJobs.objects.filter(result=selected_result)
    else:
        applied_jobs = AppliedJobs.objects.filter(result__in=['placed', 'on_hold', 'rejected'])

    return render(request, 'filtered_results.html', {'applied_jobs': applied_jobs})
def applied_jobs_delete(request,job_id):
    job = AppliedJobs.objects.get(id = job_id)
    job.delete()
    messages.success(request,'Deleted')
    return redirect('ageis_app:applied_jobs')



def blogs(request):
    testimonials = Testimonials.objects.all()
    return render(request,'blog.html',{'testimonials': testimonials})


def about_us(request):
    job_posted_count = Jobs.objects.all().count()
    applied_jobs_count = AppliedJobs.objects.all().count()
    company_count = Clients.objects.all().count()
    members_count = ExtendedUserModel.objects.all().count()
    about_us = AboutUs.objects.all()
    context = {
        'job_posted_count':job_posted_count,
        'applied_jobs_count':applied_jobs_count,
        'company_count':company_count,
        'members_count':members_count,
        'about_us':about_us,
    }
    return render(request,'about.html',context)


@login_required(login_url='ageis_app:login')
def about_us_backend(request):
    if request.method == 'POST':
        form = AboutUsAddForm(request.POST)
        if form.is_valid():
            print('FORM VALID')
            form.save()
            messages.success(request,'Added..')
            return redirect('ageis_app:about_us_backend')
    else:
        form = AboutUsAddForm()
    
    about_us = AboutUs.objects.all()
    context = {
        'form':form,
        'about_us':about_us
    }

    return render(request,'about-us-backend.html',context)




@login_required(login_url='ageis_app:login')
def aboutus_edit(request,update_id):
    update = AboutUs.objects.filter(id=update_id).first()
    if request.method == 'POST':
        form = AboutUsAddForm(request.POST,instance=update)
        if form.is_valid():
            form.save()
            messages.success(request,'Updated..')
            return redirect('ageis_app:about_us_backend')
    else:
        form = AboutUsAddForm(instance=update)

    context ={
        'form':form
    }
    return render(request,'about-us-edit.html',context)





def aboutus_delete(request,about_id):
    about = AboutUs.objects.get(id = about_id)
    about.delete()
    messages.success(request,'Deleted')
    return redirect('ageis_app:about_us_backend')





def clients(request):
    companies = Clients.objects.all()
    context = {
        'companies':companies
    }
    return render(request,'clients-frontend.html',context)




def resume_writing(request):
    return render(request,'resumewriting.html')


def interviewtips(request):
    return render(request,'interviewtips.html')


def contact_us(request):
    if request.method == 'POST':
        print(request.POST)
        name = request.POST.get('name')
        email = "support@ageisrecruitment.online"
        email1 = request.POST.get('email')
        number = request.POST.get('number')
        subject = request.POST.get('subject')
        message = request.POST.get('message')
        email_body = (
            f'Name: {name}\n'
            f'Email: {email1}\n'
            f'Phone: {number}\n'
            f'Subject: {subject}\n'
            f'Message: {message}'
        )
        send_mail(
            'Enquiry',
            email_body,
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,    
        )
        messages.success(request,'Form submited..')
        return redirect('ageis_app:contact_us')
    return render(request,'contact-us.html')

# def contact_us(request):
#     if request.method == 'POST':
#         print(request.POST)
#         form = ContactForm(request.POST)
#         form.save()
#         email = "achujoseph@a2zalphabetsolutionz.com"  # Use the correct sender email address

#         send_mail(
#             'Enquiry',
#             f'Name: {form.cleaned_data["name"]}\nEmail: {form.cleaned_data["email"]}\nMessage: {form.cleaned_data["message"]}',
#             (email),
#             [settings.EMAIL_HOST_USER],
#             fail_silently=False,    
#         )
#         print('Form submited..')
#         return render(request,'thank_you.html')
#     else:
#         form = ContactForm()
#     return render(request,'index.html', {'form': form})

def job_search(request):
    # Use GET to retrieve the 'title' from the query parameters
    job_title = request.GET.get('title')
    user = request.user

    query = Q()

    # Only add the job_title filter if job_title is not None
    if job_title:
        query &= Q(job_title__icontains=job_title)

    results = Jobs.objects.filter(query)

    # Save the first result of the search to RecentlySearchedJobs, if any
    job = results.first()
    if job and user.is_authenticated and not RecentlySearchedJobs.objects.filter(user=user, job=job).exists():
        RecentlySearchedJobs.objects.create(user=user, job=job)

    context = {
        'jobs': results
    }
    return render(request, 'jobsfrontend.html', context)

def render_template(request, template_name):
    return render(request, template_name)

def render_disclaimer(request):
    return render(request, 'disclaimer.html')

def render_terms(request):
    return render(request, 'terms.html')

def render_faq(request):
    return render(request, 'faq.html')

def render_privacy(request):
    return render(request, 'privacy.html')


def user_profile(request):

    if request.user.is_authenticated:
        users = request.user
        user = request.user.extenedusermodel  
        skills = user.skills.all()
        qualifications = user.qualifications.all()
        experiences = user.experiences.all()
        
        context = {
            'users': users,
            'user':user,
            'skills': skills,
            'qualifications': qualifications,
            'experiences': experiences,
        }
        
        return render(request, 'user_profile.html', context)
    else:
      
        return render(request, 'error.html', {'message': 'User not authenticated'})
    

def add_skill(request):
    if request.method == 'POST':
        form = SkillForm(request.POST)
        if form.is_valid():
            skill = form.save(commit=False)
            skill.user = request.user.extenedusermodel
            skill.save()
            messages.success(request, 'Skill added successfully.')
            return redirect('user_profile')
    else:
        form = SkillForm()

    return render(request, 'add_skill.html', {'form': form})

def delete_skill(request, skill_id):
    skill = get_object_or_404(Skills, id=skill_id)
    skill.delete()
    messages.success(request, 'Skill deleted successfully.')
    return redirect('ageis_app:user_profile')


def add_qualification(request):
    if request.method == 'POST':
        form = QualificationForm(request.POST)
        if form.is_valid():
            qualification = form.save(commit=False)
            qualification.user = request.user.extenedusermodel
            qualification.save()
            messages.success(request, 'Qualification added successfully.')
            return redirect('user_profile')
    else:
        form = QualificationForm()

    return render(request, 'add_qualification.html', {'form': form})

def delete_qualification(request, qualification_id):
    qualification = get_object_or_404(Qualification, id=qualification_id)
    qualification.delete()
    messages.success(request, 'Qualification deleted successfully.')
    return redirect('user_profile')

def add_experience(request):
    if request.method == 'POST':
        form = ExperienceForm(request.POST)
        if form.is_valid():
            experience = form.save(commit=False)
            experience.user = request.user.extenedusermodel
            experience.save()
            messages.success(request, 'Experience added successfully.')
            return redirect('user_profile')
    else:
        form = ExperienceForm()

    return redirect('ageis_app:user_profile')





# def delete_experience(request, experience_id):
#     experience = get_object_or_404(Experience, id=experience_id)
#     experience.delete()
#     messages.success(request, 'Experience deleted successfully.')
#     return redirect('user_profile')


@login_required
def profile_update(request):
    user_profile = ExtendedUserModel.objects.get(user=request.user)

    if request.method == 'POST':
        # Extract data from the POST request
        new_first_name = request.POST.get('firstname', '')
        new_last_name = request.POST.get('lastname', '')
        new_position = request.POST.get('position', '')
        new_company_university = request.POST.get('company', '')

        #Update the user details in the ExtendedUserModel instance
        user_profile.user.first_name = new_first_name
        user_profile.user.last_name = new_last_name
        user_profile.position = new_position
        user_profile.comapany_univercity = new_company_university

        profile_photo = request.FILES.get('pic')
        if profile_photo:
            user_profile.profile_photo = profile_photo

        # Save the changes
        user_profile.user.save()
        user_profile.save()
        return redirect('ageis_app:user_profile')
    else:
        form = ExtendedUserModelForm(instance=user_profile)

    return render(request, 'user_profile.html', {'form': form})

@login_required
def contact_update(request):
    user_profile = ExtendedUserModel.objects.get(user=request.user)

    if request.method == 'POST':
        # Extract data from the POST request
        new_phone = request.POST.get('number', '')
        new_email = request.POST.get('email', '')
        new_location = request.POST.get('location', '')
        

        #Update the user details in the ExtendedUserModel instance
        user_profile.user.email = new_email
        user_profile.phone = new_phone
        user_profile.location = new_location

        # Save the changes
        user_profile.user.save()
        user_profile.save()

        return redirect('ageis_app:user_profile')
    else:
        form = ExtendedUserModelForm(instance=user_profile)

    return render(request, 'user_profile.html', {'form': form})


def delete_qualification_view(request, qualification_id):
    if request.method == 'POST':  # Ensure it's a POST request
        qualification = get_object_or_404(Qualification, id=qualification_id)
        qualification.delete()
        
        # Return a JSON response
        return JsonResponse({'status': 'success', 'message': 'Qualification deleted successfully.'})
    
    # If not a POST request, return an error response
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=400)


def add_qualification_view(request):
    user_profile = ExtendedUserModel.objects.get(user=request.user) 
          
    if request.method == 'POST':
        completion_year = request.POST.get('year', '')
        institution = request.POST.get('university', '')
        degree = request.POST.get('qulification', '')


        if not all([degree, institution, completion_year]):
                return HttpResponseBadRequest("Invalid data submitted.")
        
        new_qualification = Qualification.objects.create(
                    user=request.user.extenedusermodel,
                    degree=degree,
                    institution=institution,
                    completion_year=completion_year
                )
    else:
        form = ExtendedUserModelForm(instance=user_profile)

    return redirect('ageis_app:user_profile')

def delete_skill_view(request, skill_id):
    if request.method == 'POST':  # Ensure it's a POST request
        skill = get_object_or_404(Skills, id=skill_id)
        skill.delete()
        
        # Return a JSON response
        return JsonResponse({'status': 'success', 'message': 'Skill deleted successfully.'})
    
    # If not a POST request, return an error response
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=400)

def add_skill(request):
    user_profile = ExtendedUserModel.objects.get(user=request.user) 
          
    if request.method == 'POST':
        skill = request.POST.get('skill', '')



        if not skill:
                return HttpResponseBadRequest("Invalid data submitted.")
        
        new_qualification = Skills.objects.create(
                    user=request.user.extenedusermodel,
                    skill=skill,
                )
    else:
        form = ExtendedUserModelForm(instance=user_profile)

    return redirect('ageis_app:user_profile')

from datetime import datetime  # Import the datetime module

def add_experience_view(request):
    if request.method == 'POST':
        # Extract data from the POST request
        company = request.POST.get('experience-com')
        position = request.POST.get('experience-position')
        start_date_str = request.POST.get('experience-start-date')
        end_date_str = request.POST.get('experience-end-date')
        details = request.POST.get('experience-details')

        # Validate the data (add your own validation logic as needed)
        if not all([company, position, start_date_str, details]):
            # Handle validation error as needed
            return render(request, 'error_template.html', {'error_message': 'Invalid data submitted'})

        # Convert date strings to datetime objects
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date() if end_date_str else None

        # Create a new experience and associate it with the current user
        new_experience = Experience.objects.create(
            user=request.user.extenedusermodel,
            company=company,
            position=position,
            start_date=start_date,
            end_date=end_date,
            description=details
        )
        return redirect('ageis_app:user_profile')

    return redirect('ageis_app:user_profile')

def change_resume_view(request):
    if request.method == 'POST' and 'resume' in request.FILES:
        user_profile = ExtendedUserModel.objects.get(user=request.user)
        user_profile.cv = request.FILES['resume']
        user_profile.save()
        return redirect('ageis_app:user_profile')
    return render(request, 'change_resume.html')


def delete_experience_view(request, experience_id):
    if request.method == 'POST':  # Ensure it's a POST request
        experience = get_object_or_404(Experience, id=experience_id)
        experience.delete()
        
        # Return a JSON response
        return JsonResponse({'status': 'success', 'message': 'Experience deleted successfully.'})
    
    # If not a POST request, return an error response
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=400)


