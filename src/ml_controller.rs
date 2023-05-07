/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
use hb_utils::ConvertError;
use ndarray::ArrayD;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error as Std_Error;
use zeroize::Zeroize;
use std::{
    fmt,
    collections::HashMap,
    fs::File,
    io::{BufReader, Write},
    path::PathBuf,
    sync::{Arc, RwLock},
};
use uuid::Uuid;
use tensorflow::{Graph, SavedModelBundle, SessionOptions, SessionRunArgs, Status, Tensor};
#[allow(unused_imports)]
use tracing::{info, warn, error};

#[derive(Clone, Debug)]
pub enum InputFormat {
    //NumpyFile(Bytes),
    Tensor,
    //Other(String),
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub struct ML_Input<'a> {
    pub input_format: InputFormat,
    pub input_tensor: &'a mut Tensor<f32>,
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub struct ML_Output {
    pub res: Result<Tensor<f32>, Status>,
    pub run_ret: Result<(), Status>,
}

#[allow(non_camel_case_types, dead_code)]
#[derive(Debug)]
pub struct ML_Model {
    path: PathBuf,
    manifest: ML_ManifestObject,
    model: SavedModelBundle,
    graph: Graph,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ModelInfo {
    model_type: String,
    accuracy: f64,
    // TODO: Figure out what else would be relevant
}

#[derive(Debug)]
pub enum MLError {
    FailedToLoadModel(String), // str is name of model
    FileNotFound,
    Unknown,
    CreationError,
    ManifestError,
    FailedToParseNpy,
    ManifestNotFound,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ML_ManifestObject {
    path: PathBuf,
    comment: String,
    cond_name: String,
    acronym: String,
    model_info: ModelInfo,
}

#[allow(non_camel_case_types, dead_code)]
pub struct ML_Controller {
    manifest_comment: String,
    manifest_objs: Vec<ML_ManifestObject>,
    models: Vec<Arc<RwLock<ML_Model>>>,
}

impl std::error::Error for MLError {}
impl fmt::Display for MLError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MLError::FailedToLoadModel(name) => write!(f, "Unable to load model `{name}`"),
            MLError::FileNotFound => write!(f, "Unable to find file for model!"),
            MLError::Unknown => write!(f, "Unknown error!"),
            MLError::CreationError => write!(f, "Failed to create model"),
            MLError::ManifestError => write!(f, "Failed to parse manifest"),
            MLError::FailedToParseNpy => write!(f, "Failed to parse Numpy File"),
            MLError::ManifestNotFound => write!(f, "Manifest file was not found!"),
        }
    }
}

impl ML_Model {
    pub fn new(manifest_obj: ML_ManifestObject ) -> Result<ML_Model, MLError> {
        info!("Loading model: \"{}\" at `{}`", manifest_obj.get_cond_name(), manifest_obj.get_path().display());
        let p = manifest_obj.path.clone();
        let mut _graph = Graph::new();
        let bundle = SavedModelBundle::load(&SessionOptions::new(), &["serve"], &mut _graph, &p)
            .convert_error(MLError::FailedToLoadModel(p.clone().to_str().unwrap().to_string()))?;

        return Ok(ML_Model {
            path: p,
            manifest: manifest_obj,
            model: bundle,
            graph: _graph,
        });
    }

    pub fn predict(&self, inp: &ML_Input) -> Result<ML_Output, Box<dyn Std_Error + Send + Sync>> {
        let tensor = inp.get_tensor();
        let sig = self
            .model
            .meta_graph_def()
            .get_signature("serving_default")?; // DO NOT CONVERT ERROR!
        let input_info = sig.get_input("input_1").unwrap_or_else(|_| {
            sig.get_input("input_2").unwrap()
        });
        let output_info = sig.get_output("dense_1")?;
        let input_op = self
            .graph
            .operation_by_name_required(&input_info.name().name)?;
        let output_op = self
            .graph
            .operation_by_name_required(&output_info.name().name)?;
        let mut args = SessionRunArgs::new();

        args.add_feed(&input_op, input_info.name().index, &tensor);
        let output_fetch = args.request_fetch(&output_op, output_info.name().index);

        let run_result = self.model.session.run(&mut args);
        //std::thread::sleep(std::time::Duration::from_millis(300));

        return Ok(ML_Output {
            res: args.fetch::<f32>(output_fetch),
            run_ret: run_result,
        });
    }
}

impl<'b> ML_Input<'b> {
    pub fn get_tensor(&'b self) -> &Tensor<f32> {
        return self.input_tensor;
    }
}

impl<'c> ML_Controller {
    pub fn new(ml_manifest: PathBuf) -> Result<ML_Controller, MLError> {
        info!("Creating new ML Controller");
        //parse the ML_Manifest
        let (manifest_entries, comment) = parse_manifest(ml_manifest)?;

        // build model from manifest model entry
        let mut model_vec: Vec<Arc<RwLock<ML_Model>>> = Vec::new();

        for entry in manifest_entries.clone() {
            let m: ML_Model = ML_Model::new(entry)?;
            model_vec.push(Arc::new(RwLock::new(m)));
        }

        return Ok(ML_Controller {
            manifest_comment: comment,
            manifest_objs: manifest_entries,
            models: model_vec,
        });
    }

    pub async fn predict<'a>(&self, inp: ML_Input<'a>) -> Vec<Result<ML_Output, Box<dyn Std_Error + Send + Sync>>> {
        let mut outs = Vec::new();
        for m in &self.models {
            // TODO: Thread this
            outs.push(m.write().unwrap()
                      .predict(&inp));
        }
        return outs;
    }

    pub fn get_manifest_len(&self) -> usize {
        return self.manifest_objs.len();
    }
    pub fn get_manifest_entry(&'c self, i: usize) -> &'c ML_ManifestObject {
        return &self.manifest_objs[i];
    }

    pub fn get_info() -> Vec<ModelInfo> {
        todo!()
    }
}

impl ML_ManifestObject {
    pub fn get_path(&self) -> PathBuf {
        return self.path.clone();
    }
    pub fn get_comment(&self) -> String {
        return self.comment.clone();
    }
    pub fn get_cond_name(&self) -> String {
        return self.cond_name.clone();
    }
    pub fn get_model_info(&self) -> ModelInfo {
        return self.model_info.clone();
    }
    pub fn get_acronym(&self) -> String {
        return self.acronym.clone();
    }
}

fn parse_manifest(manifest: PathBuf) -> Result<(Vec<ML_ManifestObject>, String), MLError> {
    info!("Parsing manifest at `{}`", manifest.display());
    let reader = BufReader::new(File::open(manifest).convert_error(MLError::ManifestNotFound)?);
    let map: HashMap<String, Value> = serde_json::from_reader(reader).convert_error(MLError::ManifestError)?;
    let cmnt = map.get("comment").unwrap().to_string();
    let models: Vec<ML_ManifestObject> =
        serde_json::from_value(map.get("models").unwrap().clone()).unwrap();

    return Ok((models, cmnt));
    // todo!()
}

pub fn tensor_from_numpy_file(fpath: &String) -> Result<Tensor<f32>, Box<dyn Std_Error + Send + Sync>> {
    info!("Creating tensor from numpy bytestream");
    // read numpy file
    let npy_array: ArrayD<f64> =
        ndarray_npy::read_npy(fpath).convert_error(MLError::FailedToParseNpy)?;

    // create tensor
    let mut tf_tensor = Tensor::new(&[
        npy_array.shape()[0] as u64,
        npy_array.shape()[1] as u64,
        npy_array.shape()[2] as u64,
        npy_array.shape()[3] as u64,
    ]);

    // convert to tensor
    let data = npy_array.as_slice().unwrap();
    let size = tf_tensor.len();
    for i in 0..size {
        tf_tensor[i] = data[i] as f32;
    }
    return Ok(tf_tensor);
}


// Securely wiping the data for ML_Input

impl Drop for ML_Input<'_> {
    fn drop(&mut self) {
        self.input_tensor.zeroize()
    }
}
