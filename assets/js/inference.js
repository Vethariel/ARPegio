/** Inferencia del autoencoder L2 en navegador (ONNX Runtime Web). */
const ArpegioInference = (function () {
  const MODEL_URL = "models/autoencoder.onnx";
  const SCALER_URL = "models/scaler.json";
  const WASM_CDN = "https://cdn.jsdelivr.net/npm/onnxruntime-web@1.22.0/dist/";

  let session = null;
  let scaler = null;
  let loadError = null;
  let loading = null;

  function transform(features) {
    if (!scaler) throw new Error("Scaler no cargado");
    const vec = scaler.features.map((name) => {
      const v = features[name];
      if (v == null || Number.isNaN(v)) {
        throw new Error(`Feature ausente: ${name}`);
      }
      return Number(v);
    });
    return vec.map((v, i) => v * scaler.scale[i] + scaler.min[i]);
  }

  function mseFromArrays(input, output) {
    let sum = 0;
    for (let i = 0; i < input.length; i++) {
      const d = output[i] - input[i];
      sum += d * d;
    }
    return sum / input.length;
  }

  async function load() {
    if (session && scaler) return true;
    if (loading) return loading;

    loading = (async () => {
      try {
        if (typeof ort === "undefined") {
          throw new Error("onnxruntime-web no está cargado");
        }
        ort.env.wasm.wasmPaths = WASM_CDN;

        const [scalerData, onnxSession] = await Promise.all([
          fetch(SCALER_URL).then((r) => {
            if (!r.ok) throw new Error(`No se pudo cargar ${SCALER_URL}`);
            return r.json();
          }),
          ort.InferenceSession.create(MODEL_URL, {
            executionProviders: ["wasm"],
          }),
        ]);

        scaler = scalerData;
        session = onnxSession;
        loadError = null;
        return true;
      } catch (err) {
        loadError = err;
        session = null;
        scaler = null;
        console.error("ArpegioInference:", err);
        return false;
      } finally {
        loading = null;
      }
    })();

    return loading;
  }

  async function score(features) {
    if (!session || !scaler) {
      const ok = await load();
      if (!ok) throw loadError || new Error("Modelo no disponible");
    }

    const input = transform(features);
    const inputTensor = new ort.Tensor(
      "float32",
      Float32Array.from(input),
      [1, input.length]
    );
    const outputs = await session.run({ features: inputTensor });
    const reconstruction = outputs.reconstruction?.data;
    if (!reconstruction) {
      throw new Error("Salida ONNX inválida");
    }
    return mseFromArrays(input, reconstruction);
  }

  function isReady() {
    return Boolean(session && scaler);
  }

  function getStatus() {
    if (loadError) return { state: "error", message: loadError.message };
    if (session && scaler) return { state: "ready" };
    if (loading) return { state: "loading" };
    return { state: "idle" };
  }

  function setStatusBadge() {
    const el = document.getElementById("lab-model-status");
    if (!el) return;
    const st = getStatus();
    if (st.state === "ready") {
      el.textContent = "Motor ONNX · WASM · listo";
      el.style.color = "var(--normal)";
    } else if (st.state === "loading") {
      el.textContent = "Cargando modelo ONNX…";
      el.style.color = "var(--amber)";
    } else if (st.state === "error") {
      el.textContent = `ONNX no disponible · ${st.message}`;
      el.style.color = "var(--danger)";
    } else {
      el.textContent = "Motor ONNX · pendiente";
      el.style.color = "var(--faint)";
    }
  }

  return {
    load,
    score,
    isReady,
    getStatus,
    setStatusBadge,
    transform,
  };
})();
