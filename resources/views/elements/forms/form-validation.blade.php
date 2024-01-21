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
                            <div class="card-title text-slate-900 dark:text-white">Simple Form Validation</div>
                        </div>
                    </header>
                    <div class="card-text h-full">
                        <form class="space-y-4" id="loginForm">
                            <div class="input-area">
                                <label for="name" class="form-label">Username</label>
                                <div class="relative">
                                    <input id="name" type="text" class="form-control pr-9" placeholder="Username">
                                </div>
                                <span id="nameErrorMsg" class="font-Inter text-sm text-danger-500 pt-2 hidden mt-1">This is valid state.</span>
                            </div>
                            <div class="input-area">
                                <label for="email" class="form-label">Email</label>
                                <div class="relative">
                                    <input id="email" type="email" class="form-control" placeholder="Enter Your Email"></div>
                                    <span id="emailErrorMsg" class="font-Inter text-sm text-danger-500 pt-2 hidden mt-1"></span>
                            </div>
                            <button class="btn flex justify-center btn-dark ml-auto">Submit</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Simple Form Validation With Tootltips</div>
                        </div>
                    </header>
                    <div class="card-text h-full">
                        <form class="space-y-4" id="tooltipValidation">
                            <div class="input-area">
                                <label for="tooltip_name" class="form-label">Username</label>
                                <input id="tooltip_name" name="tooltip_name" type="text" class="form-control" placeholder="Username"></div>
                            <div class="input-area">
                                <label for="tooltip_email" class="form-label">Email</label>
                                <input id="tooltip_email" name="tooltip_email" type="email" class="form-control" placeholder="Enter Your Email" required="required"></div>
                            <button class="btn flex justify-center btn-dark ml-auto">Submit</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="card xl:col-span-2">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Validating Multiple Rules</div>
                        </div>
                    </header>
                    <div class="card-text h-full">
                        <form class="space-y-4" id="multipleValidation">
                            <div class="grid md:grid-cols-2 gap-6">
                                <div class="input-area">
                                    <label for="name" class="form-label">Username</label>
                                    <div class="relative">
                                        <input id="name" type="text" name="name" class="form-control" placeholder="Username" required="required"></div>
                                </div>
                                <div class="input-area">
                                    <label for="email" class="form-label">Email</label>
                                    <div class="relative">
                                        <input id="email" type="email" name="email" class="form-control" placeholder="Enter Your Email" required="required">
                                        <iconify-icon class="absolute top-1/2 right-3 -translate-y-1/2 text-danger-500 text-xl" icon="mdi:warning-octagon-outline"></iconify-icon>
                                    </div>
                                    <span class="font-Inter text-sm text-danger-500 pt-2 inline-block">This is invalid state.</span>
                                </div>
                                <div class="input-area">
                                    <label for="password" class="form-label">Password</label>
                                    <div class="relative">
                                        <input id="password" type="password" name="password" class="form-control pr-9" placeholder="Password" required="required">
                                        <button id="passIcon" class="passIcon absolute top-2.5 right-3 text-slate-300 text-xl p-0 leading-none" type="button">
                                            <iconify-icon id="passwordhide" class="inline-block" icon="heroicons-solid:eye-off"></iconify-icon>
                                            <iconify-icon id="passwordshow" class="hidden" icon="heroicons-outline:eye"></iconify-icon>
                                        </button>
                                    </div>
                                    <span class="font-Inter text-sm text-danger-500 pt-2 inline-block">This is invalid state.</span>
                                </div>
                                <div class="input-area">
                                    <label for="confirm_password" class="form-label">Confirm Password</label>
                                    <div class="relative">
                                        <input id="confirm_password" type="password" name="confirm_password" class="form-control pr-9" placeholder="Password" required="required">
                                        <button id="ConfirmpassIcon" class="absolute top-2.5 right-3 text-slate-300 text-xl p-0 leading-none" type="button">
                                            <iconify-icon id="passwordhide" class="inline-block" icon="heroicons-solid:eye-off"></iconify-icon>
                                            <iconify-icon id="passwordshow" class="hidden" icon="heroicons-outline:eye"></iconify-icon>
                                        </button>
                                    </div>
                                    <span class="font-Inter text-sm text-danger-500 pt-2 inline-block">This is invalid state.</span>
                                </div>
                            </div>
                            <button class="btn flex justify-center btn-dark ml-auto">Submit</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="card xl:col-span-2">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Validation Types</div>
                        </div>
                    </header>
                    <div class="card-text h-full">
                        <form class="space-y-4" id="typeValidation">
                            <div class="grid md:grid-cols-2 gap-7">
                                <div class="input-area">
                                    <label for="name" class="form-label">Username</label>
                                    <input id="name" name="name" type="text" class="form-control" placeholder="Username"></div>
                                <div class="input-area">
                                    <label for="number" class="form-label">Must Only Consist Of Numbers</label>
                                    <input id="number" name="number" type="text" class="form-control" placeholder="Enter Number only"></div>
                                <div class="input-area">
                                    <label for="rangeType" class="form-label">Range Value</label>
                                    <input id="rangeType" name="rangeType" type="number" class="form-control" placeholder="Enter number from 0 to 50"></div>
                                <div class="input-area">
                                    <label for="alphabeticCharacter" class="form-label">Alphabetic Characters</label>
                                    <input id="alphabeticCharacter" name="alphabeticCharacter" type="text" class="form-control" placeholder="Enter Character Only"></div>
                                <div class="input-area">
                                    <label for="specifiedLength" class="form-label">Length Should Not Be Less Than The Specified Length : 3</label>
                                    <input id="specifiedLength" name="specifiedLength" type="text" class="form-control" placeholder="Enter Minimum 3 Characters"></div>
                                <div class="input-area">
                                    <label for="Password" class="form-label">Password</label>
                                    <input id="Password" name="Password" type="password" class="form-control" placeholder="Enter Your Password"></div>
                                <div class="input-area">
                                    <label for="url" class="form-label">Must Be A Valid Url</label>
                                    <input id="url" name="url" type="url" class="form-control" placeholder="Enter Valid URL"></div>
                                <div class="input-area">
                                    <label for="textMsg" class="form-label">Message</label>
                                    <textarea name="textMsg" id="textMsg" rows="5" class="form-control" placeholder="Your Message"></textarea>
                                </div>
                            </div>
                            <button class="btn flex justify-center btn-dark">Submit</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</x-app-layout>
