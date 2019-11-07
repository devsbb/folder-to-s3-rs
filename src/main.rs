use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use failure::ResultExt;
use rusoto_core::Region;
use rusoto_s3::{HeadBucketRequest, PutObjectRequest, S3Client, S3};
use structopt::StructOpt;
use url::Url;

type Result<T> = std::result::Result<T, failure::Error>;

#[derive(StructOpt, Debug)]
struct Options {
    #[structopt(short = "r", long, help = "AWS Region to connect to")]
    aws_region: Region,
    local_folder: PathBuf,
    remote_folder: Url,
}

fn get_all_files(folder: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut output = vec![];
    for entry in folder
        .read_dir()
        .with_context(|_| format!("Failed to read contents of {}", folder.to_string_lossy()))?
    {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            output.extend(get_all_files(&entry.path())?)
        } else {
            output.push(entry.path())
        }
    }
    Ok(output)
}

fn main() -> Result<()> {
    let options: Options = Options::from_args();
    if options.remote_folder.scheme() != "s3" {
        eprintln!(
            "Cannot use {} as schema, only s3",
            options.remote_folder.scheme()
        );
        std::process::exit(1);
    }

    if !options.local_folder.exists() {
        eprintln!(
            "{:?} is not a valid folder",
            options.local_folder.to_string_lossy()
        );
        std::process::exit(1);
    }

    let cli = S3Client::new(options.aws_region);
    let bucket = options.remote_folder.host().unwrap().to_string();
    cli.head_bucket(HeadBucketRequest {
        bucket: bucket.clone(),
    })
    .sync()
    .with_context(|_| format!("Failed to check if bucket {:?} exists", bucket))?;

    let bucket_folder = &options.remote_folder.path()[1..];

    for file_path in get_all_files(&options.local_folder)? {
        let key = get_key(bucket_folder, &options.local_folder, &file_path)?;
        println!("Uploading {} to {}", file_path.to_string_lossy(), key);
        upload_file(&bucket, key, &file_path, &cli)?;
        println!("Done");
    }

    Ok(())
}

fn get_key(bucket_folder: &str, base_folder: &PathBuf, local_file: &PathBuf) -> Result<String> {
    let mut output = vec![bucket_folder];

    let relative_path = local_file.strip_prefix(base_folder)?;
    let relative_path = relative_path.to_string_lossy();
    output.push(relative_path.as_ref());

    Ok(output.join("/"))
}

fn upload_file(
    bucket: &str,
    key: String,
    file_path: &PathBuf,
    cli: &S3Client,
) -> Result<()> {
    let mut file = File::open(file_path)
        .context("Error opening file to upload")?;

    // TODO: Use async version to avoid memory issues
    let mut file_data = vec![];
    file.read_to_end(&mut file_data)
        .context("Error reading file's content")?;
    let digest = md5::compute(&file_data);
    let request = PutObjectRequest {
        bucket: bucket.to_string(),
        body: Some(file_data.into()),
        content_md5: Some(base64::encode(digest.as_ref())),
        key,
        ..Default::default()
    };
    let _response = cli.put_object(request).sync()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::get_key;

    #[test]
    fn test_get_key() {
        let key = get_key(
            "/root",
            &["home", "user"].iter().collect(),
            &["home", "user", "Videos", "Guda", "bola.mkv"]
                .iter()
                .collect(),
        )
        .unwrap();
        assert_eq!(key, "/root/Videos/Guda/bola.mkv");
    }
}