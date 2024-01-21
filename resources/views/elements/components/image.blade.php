<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="space-y-6">
            <!-- Basic Image -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Images</div>
                        </div>
                    </header>
                    <div class="card-text h-full "> <img src="images/all-img/image-1.png" class="rounded-md" alt="image"> </div>
                </div>
            </div>
            <!-- Responsive Image -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Responsive Images</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <h6 class="block text-base font-medium tracking-[0.01em] dark:text-slate-300 text-slate-500 uppercase mb-6">SMALL IMAGE
                                WITH FLUID:</h6> <img src="images/all-img/image-2.png" class="rounded-md" alt="image"> </div>
                    <div class="card-text h-full ">
                        <h6 class="block text-base font-medium tracking-[0.01em] dark:text-slate-300 text-slate-500 uppercase mb-6 mt-5">LARGE
                                IMAGE WITH FLUID-GROW:</h6> <img src="images/all-img/image-3.png" class="rounded-md w-full" alt="image"> </div>
                </div>
            </div>
            <!-- Responsive Image -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Responsive Images</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="grid xl:grid-cols-6 lg:grid-cols-3 md:grid-cols-3 grid-cols-1 gap-5"> <img src="images/all-img/thumb-1.png" class="rounded-md border-4 border-slate-300 max-w-full w-full block" alt="image"> <img src="images/all-img/thumb-2.png" class="rounded-md border-4 border-slate-300 max-w-full w-full block" alt="image"> <img src="images/all-img/thumb-3.png" class="rounded-md border-4 border-slate-300 max-w-full w-full block" alt="image"> <img src="images/all-img/thumb-4.png" class="rounded-md border-4 border-slate-300 max-w-full w-full block" alt="image"> <img src="images/all-img/thumb-5.png" class="rounded-md border-4 border-slate-300 max-w-full w-full block" alt="image"> <img src="images/all-img/thumb-6.png" class="rounded-md border-4 border-slate-300 max-w-full w-full block" alt="image"> </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</x-app-layout>
