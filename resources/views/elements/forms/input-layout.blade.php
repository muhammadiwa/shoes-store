<x-app-layout>
    <div class="space-y-8">
        <div>
            <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="grid xl:grid-cols-2 grid-cols-1 gap-6">
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Horizontal Form</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <form class="space-y-4">
                            <div class="input-area relative pl-28">
                                <label for="largeInput" class="inline-inputLabel">Full Name</label>
                                <input type="text" class="form-control" placeholder="Full Name">
                            </div>
                            <div class="input-area relative pl-28">
                                <label for="largeInput" class="inline-inputLabel">Email</label>
                                <input type="email" class="form-control" placeholder="Enter Your Email">
                            </div>
                            <div class="input-area relative pl-28">
                                <label for="largeInput" class="inline-inputLabel">Phone</label>
                                <input type="tel" class="form-control" placeholder="Phone Number" pattern="[0-9]">
                            </div>
                            <div class="input-area relative pl-28">
                                <label for="largeInput" class="inline-inputLabel">Password</label>
                                <input type="password" class="form-control" placeholder="8+ characters, 1 capitat letter">
                            </div>
                            <div class="checkbox-area ltr:pl-28 rtl:pr-28">
                                <label class="inline-flex items-center cursor-pointer">
                                    <input type="checkbox" class="hidden" name="checkbox">
                                    <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative
                                            transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                        <img src="images/icon/ck-white.svg" alt="" class="h-[10px] w-[10px] block m-auto opacity-0">
                                    </span>
                                    <span class="text-slate-500 dark:text-slate-400 text-sm leading-6">Remember me</span>
                                </label>
                            </div>
                            <button class="btn inline-flex justify-center btn-dark ml-28">Submit</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Horizontal Form With Icons</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <form class="space-y-4">
                            <div class="input-area relative pl-28">
                                <label for="largeInput" class="inline-inputLabel">Full Name</label>
                                <div class="relative">
                                    <input type="text" class="form-control !pl-9" placeholder="Full Name">
                                    <iconify-icon icon="heroicons-outline:user" class="absolute left-2 top-1/2 -translate-y-1/2 text-base text-slate-500"></iconify-icon>
                                </div>
                            </div>
                            <div class="input-area relative pl-28">
                                <label for="largeInput" class="inline-inputLabel">Email</label>
                                <div class="relative">
                                    <input type="email" class="form-control !pl-9" placeholder="Your Email">
                                    <iconify-icon icon="heroicons-outline:mail" class="absolute left-2 top-1/2 -translate-y-1/2 text-base text-slate-500"></iconify-icon>
                                </div>
                            </div>
                            <div class="input-area relative pl-28">
                                <label for="largeInput" class="inline-inputLabel">Phone</label>
                                <div class="relative">
                                    <input type="tel" class="form-control !pl-9" placeholder="Phone Number" pattern="[0-9]">
                                    <iconify-icon icon="heroicons-outline:phone" class="absolute left-2 top-1/2 -translate-y-1/2 text-base text-slate-500"></iconify-icon>
                                </div>
                            </div>
                            <div class="input-area relative pl-28">
                                <label for="largeInput" class="inline-inputLabel">Password</label>
                                <div class="relative">
                                    <input type="tel" class="form-control !pl-9" placeholder="8+ characters, 1 capitat letter">
                                    <iconify-icon icon="heroicons-outline:lock-closed" class="absolute left-2 top-1/2 -translate-y-1/2 text-base text-slate-500"></iconify-icon>
                                </div>
                            </div>
                            <div class="checkbox-area ltr:pl-28 rtl:pr-28">
                                <label class="inline-flex items-center cursor-pointer">
                                    <input type="checkbox" class="hidden" name="checkbox">
                                    <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative
                                            transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                        <img src="images/icon/ck-white.svg" alt="checkbox" class="h-[10px] w-[10px] block m-auto opacity-0">
                                    </span>
                                    <span class="text-slate-500 dark:text-slate-400 text-sm leading-6">Remember me</span>
                                </label>
                            </div>
                            <button class="btn inline-flex justify-center btn-dark ml-28">Submit</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Vertical Form</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <form class="space-y-4">
                            <div class="input-area relative">
                                <label for="largeInput" class="form-label">Full Name</label>
                                <input type="text" class="form-control" placeholder="Full Name">
                            </div>
                            <div class="input-area relative">
                                <label for="largeInput" class="form-label">Email</label>
                                <input type="email" class="form-control" placeholder="Enter Your Email">
                            </div>
                            <div class="input-area relative">
                                <label for="largeInput" class="form-label">Phone</label>
                                <input type="tel" class="form-control" placeholder="Phone Number" pattern="[0-9]">
                            </div>
                            <div class="input-area relative">
                                <label for="largeInput" class="form-label">Password</label>
                                <input type="password" class="form-control" placeholder="8+ characters, 1 capitat letter">
                            </div>
                            <div class="checkbox-area">
                                <label class="inline-flex items-center cursor-pointer">
                                    <input type="checkbox" class="hidden" name="checkbox">
                                    <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative
                                            transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                        <img src="images/icon/ck-white.svg" alt="" class="h-[10px] w-[10px] block m-auto opacity-0">
                                    </span>
                                    <span class="text-slate-500 dark:text-slate-400 text-sm leading-6">Remember me</span>
                                </label>
                            </div>
                            <button class="btn inline-flex justify-center btn-dark">Submit</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Vertical Form With Icons</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <form class="space-y-4">
                            <div class="input-area relative">
                                <label for="largeInput" class="form-label">Full Name</label>
                                <div class="relative">
                                    <input type="text" class="form-control !pl-9" placeholder="Full Name">
                                    <iconify-icon icon="heroicons-outline:user" class="absolute left-2 top-1/2 -translate-y-1/2 text-base text-slate-500"></iconify-icon>
                                </div>
                            </div>
                            <div class="input-area relative">
                                <label for="largeInput" class="form-label">Email</label>
                                <div class="relative">
                                    <input type="email" class="form-control !pl-9" placeholder="Your Email">
                                    <iconify-icon icon="heroicons-outline:mail" class="absolute left-2 top-1/2 -translate-y-1/2 text-base text-slate-500"></iconify-icon>
                                </div>
                            </div>
                            <div class="input-area relative">
                                <label for="largeInput" class="form-label">Phone</label>
                                <div class="relative">
                                    <input type="tel" class="form-control !pl-9" placeholder="Phone Number" pattern="[0-9]">
                                    <iconify-icon icon="heroicons-outline:phone" class="absolute left-2 top-1/2 -translate-y-1/2 text-base text-slate-500"></iconify-icon>
                                </div>
                            </div>
                            <div class="input-area relative">
                                <label for="largeInput" class="form-label">Password</label>
                                <div class="relative">
                                    <input type="tel" class="form-control !pl-9" placeholder="8+ characters, 1 capitat letter">
                                    <iconify-icon icon="heroicons-outline:lock-closed" class="absolute left-2 top-1/2 -translate-y-1/2 text-base text-slate-500"></iconify-icon>
                                </div>
                            </div>
                            <div class="checkbox-area">
                                <label class="inline-flex items-center cursor-pointer">
                                    <input type="checkbox" class="hidden" name="checkbox">
                                    <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative
                                            transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                        <img src="images/icon/ck-white.svg" alt="checkbox" class="h-[10px] w-[10px] block m-auto opacity-0">
                                    </span>
                                    <span class="text-slate-500 dark:text-slate-400 text-sm leading-6">Remember me</span>
                                </label>
                            </div>
                            <button class="btn inline-flex justify-center btn-dark">Submit</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="card xl:col-span-2">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Multiple Column</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <form class="space-y-4">
                            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-7">
                                <div class="input-area relative">
                                    <label for="largeInput" class="form-label">Full Name</label>
                                    <input type="text" class="form-control" placeholder="Full Name">
                                </div>
                                <div class="input-area relative">
                                    <label for="largeInput" class="form-label">Email</label>
                                    <input type="email" class="form-control" placeholder="Enter Your Email">
                                </div>
                                <div class="input-area relative">
                                    <label for="largeInput" class="form-label">Phone</label>
                                    <input type="tel" class="form-control" placeholder="Phone Number" pattern="[0-9]">
                                </div>
                                <div class="input-area relative">
                                    <label for="largeInput" class="form-label">Password</label>
                                    <input type="password" class="form-control" placeholder="8+ characters, 1 capitat letter">
                                </div>
                                <div class="input-area relative">
                                    <label for="largeInput" class="form-label">Company</label>
                                    <input type="text" class="form-control" placeholder="Company">
                                </div>
                                <div class="input-area">
                                    <label for="select" class="form-label">Country</label>
                                    <select id="select" class="form-control">
                                        <option value="option1" class="dark:bg-slate-700">Country 1</option>
                                        <option value="option2" class="dark:bg-slate-700">Country 2</option>
                                        <option value="option3" class="dark:bg-slate-700">Country 3</option>
                                        <option value="option4" class="dark:bg-slate-700">Country 4</option>
                                    </select>
                                </div>
                            </div>
                            <div class="checkbox-area">
                                <label class="inline-flex items-center cursor-pointer">
                                    <input type="checkbox" class="hidden" name="checkbox">
                                    <span class="h-4 w-4 border flex-none border-slate-100 dark:border-slate-800 rounded inline-flex ltr:mr-3 rtl:ml-3 relative
                                            transition-all duration-150 bg-slate-100 dark:bg-slate-900">
                                        <img src="images/icon/ck-white.svg" alt="" class="h-[10px] w-[10px] block m-auto opacity-0">
                                    </span>
                                    <span class="text-slate-500 dark:text-slate-400 text-sm leading-6">Remember me</span>
                                </label>
                            </div>
                            <button class="btn inline-flex justify-center btn-dark">Submit</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</x-app-layout>