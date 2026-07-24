//! Windows-only: embed the bear icon + version-info metadata into the exe.
//! No-op on non-Windows (CI builds voli-index-tool on Linux).
//!
//! Icon generation: if `assets/voli.ico` does not exist, it is generated from
//! `assets/logo.png` (multi-size 16/24/32/48/64/128/256). To regenerate
//! manually, delete `assets/voli.ico` and rebuild.

fn main() {
    #[cfg(windows)]
    {
        use std::path::PathBuf;

        let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let workspace = manifest_dir.parent().unwrap().parent().unwrap();
        let logo = workspace.join("assets/logo.png");
        let ico_path = workspace.join("assets/voli.ico");

        if !ico_path.exists() && logo.exists() {
            generate_ico(&logo, &ico_path);
        }

        if ico_path.exists() {
            let mut res = winresource::WindowsResource::new();
            res.set_icon(ico_path.to_str().unwrap());
            res.set("ProductName", "voli");
            res.set("ProductVersion", env!("CARGO_PKG_VERSION"));
            res.set("FileDescription", "voli — fast, no-admin package manager");
            res.set("LegalCopyright", "MIT OR Apache-2.0");
            res.set("OriginalFilename", "voli.exe");
            res.compile().expect("failed to compile windows resources");
        }
    }
}

#[cfg(windows)]
fn generate_ico(logo: &std::path::Path, out: &std::path::Path) {
    use image::GenericImageView;
    use image::imageops::FilterType;

    let img = image::open(logo).expect("cannot open assets/logo.png");
    let sizes: &[u32] = &[16, 24, 32, 48, 64, 128, 256];

    let mut dir = ico::IconDir::new(ico::ResourceType::Icon);
    for &s in sizes {
        let resized = img.resize_exact(s, s, FilterType::Lanczos3);
        let rgba = resized.to_rgba8();
        let (w, h) = resized.dimensions();
        let image = ico::IconImage::from_rgba_data(w, h, rgba.into_raw());
        let entry = ico::IconDirEntry::encode(&image).expect("failed to encode icon entry");
        dir.add_entry(entry);
    }

    let mut buf = Vec::new();
    dir.write(&mut buf).expect("failed to serialize icon");
    std::fs::write(out, &buf).expect("failed to write assets/voli.ico");
    println!(
        "cargo:warning=generated {} ({} bytes)",
        out.display(),
        buf.len()
    );
}
