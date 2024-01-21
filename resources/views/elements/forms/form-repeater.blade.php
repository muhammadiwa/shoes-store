<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="card">
            <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                    <div class="flex-1">
                        <div class="card-title text-slate-900 dark:text-white">Repeating Forms</div>
                    </div>
                    <button class="btn inline-flex justify-center btn-outline-dark !bg-black-500 !text-white">
                        <span class="flex items-center">
                          <iconify-icon class="text-2xl ltr:mr-2 rtl:ml-2" icon="ic:round-plus"></iconify-icon>
                          <span>Add New</span>
                        </span>
                    </button>
                </header>
                <div class="card-text h-full ">
                    <form>
                        <div class="from-group">
                            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                <div class="input-area">
                                    <label for="firstName" class="form-label">First Name</label>
                                    <input id="firstName" type="text" class="form-control" value="Bill" placeholder="First Name">
                                </div>
                                <div class="input-area">
                                    <label for="lastName" class="form-label">Last Name</label>
                                    <input id="lastName" type="text" class="form-control" value="Jhone" placeholder="Last Name">
                                </div>
                                <div class="flex justify-between items-end space-x-6">
                                    <div class="input-area w-full">
                                        <label for="phone" class="form-label">Phone Number</label>
                                        <input id="phone" type="tel" class="form-control" value="1234569870" placeholder="Phone Number">
                                    </div>
                                    <button class="inline-flex items-center justify-center h-10 w-10 bg-danger-500 text-lg border rounded border-danger-500
                                                    text-white rb-zeplin-focused">
                                        <iconify-icon icon="fluent:delete-20-regular"></iconify-icon>
                                    </button>
                                </div>
                            </div>
                        </div>
                        <button class="btn flex justify-center btn-dark mt-5 ml-auto">Submit</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</x-app-layout>
