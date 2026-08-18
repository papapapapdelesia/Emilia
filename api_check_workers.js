export default {
  async fetch(request) {
    // CORS: izinkan akses dari origin mana pun (worker dipanggil scanner non-browser)
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "*",
      "Access-Control-Max-Age": "86400",
    };

    // Preflight browser
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // Batasi hanya GET
    if (request.method !== "GET") {
      return new Response(
        JSON.stringify(
          {
            error: "Method Not Allowed",
            message: "Only GET requests are allowed",
          },
          null,
          2
        ),
        {
          status: 405,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        }
      );
    }

    // Dapatkan Cloudflare info
    const cf = request.cf ?? {};

    // Ambil IP dari berbagai sumber
    const cfConnectingIP = request.headers.get("CF-Connecting-IP");
    const cfConnectingIPv4 = request.headers.get("CF-Connecting-IPv4");
    const trueClientIP = request.headers.get("True-Client-IP");
    const xForwardedFor = request.headers.get("X-Forwarded-For");
    const xRealIP = request.headers.get("X-Real-IP");

    // Fungsi deteksi jenis IP (validasi ketat, bukan regex longgar)
    const isIPv4 = (ip) => {
      const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip ?? "");
      if (!m) return false;
      return m.slice(1).every((octet) => +octet <= 255);
    };
    const isIPv6 = (ip) => {
      if (!ip || !ip.includes(":")) return false;
      // "::" boleh muncul maksimal sekali (kompresi)
      if (ip.includes("::") && ip.match(/::/g).length !== 1) return false;
      const compressed = ip.includes("::");
      let head, tail;
      if (compressed) {
        const parts = ip.split("::");
        head = parts[0] ? parts[0].split(":") : [];
        tail = parts[1] ? parts[1].split(":") : [];
      } else {
        const groups = ip.split(":");
        if (groups.length !== 8) return false;
        head = groups;
        tail = [];
      }
      const groups = head.concat(tail);
      // Dengan "::", maksimal 7 grup eksplisit (kompresi minimal 1 grup)
      if (compressed && groups.length > 7) return false;
      for (const g of groups) {
        if (g.includes(".")) {
          if (!isIPv4(g)) return false; // IPv4-mapped, misal ::ffff:1.2.3.4
        } else if (!/^[0-9a-fA-F]{1,4}$/.test(g)) {
          return false;
        }
      }
      return true;
    };

    // Analisis X-Forwarded-For
    let xForwardedIps = [];
    if (xForwardedFor) {
      xForwardedIps = xForwardedFor.split(",").map((ip) => ip.trim());
    }

    // Temukan IPv4 dan IPv6
    let ipv4 = null;
    let ipv6 = null;

    // Prioritaskan header Cloudflare
    if (cfConnectingIPv4 && isIPv4(cfConnectingIPv4)) {
      ipv4 = cfConnectingIPv4;
    }
    if (cfConnectingIP) {
      if (isIPv6(cfConnectingIP)) {
        ipv6 = cfConnectingIP;
      } else if (isIPv4(cfConnectingIP) && !ipv4) {
        ipv4 = cfConnectingIP;
      }
    }

    // Fallback ke header lain
    if (!ipv4 && trueClientIP && isIPv4(trueClientIP)) ipv4 = trueClientIP;
    if (!ipv4 && xRealIP && isIPv4(xRealIP)) ipv4 = xRealIP;

    // Cek X-Forwarded-For chain
    if (xForwardedIps.length > 0) {
      const clientIp = xForwardedIps[0];
      if (!ipv4 && isIPv4(clientIp)) ipv4 = clientIp;
      if (!ipv6 && isIPv6(clientIp)) ipv6 = clientIp;
    }

    // Format tanggal menjadi dd-mm-yyyy HH:MM:SS
    const now = new Date();
    const timestamp = `${now.getDate().toString().padStart(2, "0")}-${(
      now.getMonth() + 1
    )
      .toString()
      .padStart(2, "0")}-${now.getFullYear()} ${now
      .getHours()
      .toString()
      .padStart(2, "0")}:${now.getMinutes().toString().padStart(2, "0")}:${now
      .getSeconds()
      .toString()
      .padStart(2, "0")}`;

    // Format ISO untuk kompatibilitas
    const timestampISO = now.toISOString();

    // Siapkan hasil
    const result = {
      // Informasi IP
      ip: ipv6 || ipv4 || "unknown",
      ipv4: ipv4,
      ipv6: ipv6,
      has_dual_stack: !!(ipv4 && ipv6),

      // Timestamp dalam format yang diminta
      timestamp: timestamp,
      timestamp_iso: timestampISO,

      // Informasi geolokasi lengkap
      country: cf.country ?? null,
      country_name: cf.countryName ?? getCountryName(cf.country),
      city: cf.city ?? null,
      region: cf.region ?? null,
      region_code: cf.regionCode ?? null,
      timezone: cf.timezone ?? null,
      continent: cf.continent ?? null,
      latitude: cf.latitude ?? null,
      longitude: cf.longitude ?? null,
      postal_code: cf.postalCode ?? null,

      // Informasi jaringan
      asn: cf.asn ?? null,
      as_organization: cf.asOrganization ?? null,
      colo: cf.colo ?? null,

      // Informasi koneksi
      http_protocol: cf.httpProtocol ?? null,
      tls_version: cf.tlsVersion ?? null,
      tls_cipher: cf.tlsCipher ?? null,

      // Informasi request
      user_agent: request.headers.get("User-Agent") ?? null,
      accept_language: request.headers.get("Accept-Language") ?? null,
      accept_encoding: cf.clientAcceptEncoding ?? null,
      request_method: request.method,

      // Informasi tambahan Cloudflare
      is_eu_country: cf.isEUCountry ?? null,
      client_tcp_rtt: cf.clientTcpRtt ?? null,
      edge_request_keep_alive_status: cf.edgeRequestKeepAliveStatus ?? null,
      request_priority: cf.requestPriority ?? null,
    };

    // Filter null values untuk response yang lebih bersih
    const filteredResult = Object.fromEntries(
      Object.entries(result).filter(([_, v]) => v !== null)
    );

    return new Response(JSON.stringify(filteredResult, null, 2), {
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store, max-age=0",
        "X-Content-Type-Options": "nosniff",
        ...corsHeaders,
      },
    });
  },
};

// Helper function untuk mendapatkan nama negara dari kode
function getCountryName(countryCode) {
  const countryNames = {
    // ===== ASEAN =====
    ID: "Indonesia",
    SG: "Singapore",
    MY: "Malaysia",
    TH: "Thailand",
    VN: "Vietnam",
    PH: "Philippines",
    BN: "Brunei",
    KH: "Cambodia",
    LA: "Laos",
    MM: "Myanmar",
    TL: "Timor-Leste",
    JP: "Japan",
    KR: "South Korea",
    KP: "North Korea",
    CN: "China",
    TW: "Taiwan",
    HK: "Hong Kong",
    MO: "Macau",
    IN: "India",
    PK: "Pakistan",
    BD: "Bangladesh",
    LK: "Sri Lanka",
    NP: "Nepal",
    BT: "Bhutan",
    MV: "Maldives",
    AF: "Afghanistan",
    KZ: "Kazakhstan",
    UZ: "Uzbekistan",
    TM: "Turkmenistan",
    KG: "Kyrgyzstan",
    TJ: "Tajikistan",
    MN: "Mongolia",
    SA: "Saudi Arabia",
    AE: "United Arab Emirates",
    QA: "Qatar",
    KW: "Kuwait",
    BH: "Bahrain",
    OM: "Oman",
    YE: "Yemen",
    IL: "Israel",
    PS: "Palestine",
    TR: "Turkey",
    IR: "Iran",
    IQ: "Iraq",
    SY: "Syria",
    JO: "Jordan",
    LB: "Lebanon",
    GB: "United Kingdom",
    IE: "Ireland",
    FR: "France",
    DE: "Germany",
    NL: "Netherlands",
    BE: "Belgium",
    LU: "Luxembourg",
    CH: "Switzerland",
    AT: "Austria",
    IT: "Italy",
    ES: "Spain",
    PT: "Portugal",
    NO: "Norway",
    SE: "Sweden",
    FI: "Finland",
    DK: "Denmark",
    IS: "Iceland",
    PL: "Poland",
    CZ: "Czech Republic",
    SK: "Slovakia",
    HU: "Hungary",
    RO: "Romania",
    BG: "Bulgaria",
    GR: "Greece",
    HR: "Croatia",
    SI: "Slovenia",
    RS: "Serbia",
    BA: "Bosnia and Herzegovina",
    ME: "Montenegro",
    AL: "Albania",
    MK: "North Macedonia",
    EE: "Estonia",
    LV: "Latvia",
    LT: "Lithuania",
    UA: "Ukraine",
    BY: "Belarus",
    MD: "Moldova",
    RU: "Russia",
    US: "United States",
    CA: "Canada",
    MX: "Mexico",
    BR: "Brazil",
    AR: "Argentina",
    CL: "Chile",
    CO: "Colombia",
    PE: "Peru",
    VE: "Venezuela",
    EC: "Ecuador",
    BO: "Bolivia",
    PY: "Paraguay",
    UY: "Uruguay",
    GY: "Guyana",
    SR: "Suriname",
    CR: "Costa Rica",
    PA: "Panama",
    GT: "Guatemala",
    HN: "Honduras",
    SV: "El Salvador",
    NI: "Nicaragua",
    CU: "Cuba",
    DO: "Dominican Republic",
    HT: "Haiti",
    JM: "Jamaica",
    ZA: "South Africa",
    EG: "Egypt",
    MA: "Morocco",
    DZ: "Algeria",
    TN: "Tunisia",
    LY: "Libya",
    NG: "Nigeria",
    GH: "Ghana",
    CI: "Ivory Coast",
    SN: "Senegal",
    ML: "Mali",
    BF: "Burkina Faso",
    NE: "Niger",
    KE: "Kenya",
    TZ: "Tanzania",
    UG: "Uganda",
    RW: "Rwanda",
    BI: "Burundi",
    ET: "Ethiopia",
    SO: "Somalia",
    SD: "Sudan",
    SS: "South Sudan",
    CM: "Cameroon",
    AO: "Angola",
    MZ: "Mozambique",
    ZM: "Zambia",
    ZW: "Zimbabwe",
    NA: "Namibia",
    BW: "Botswana",
    MG: "Madagascar",
    AU: "Australia",
    NZ: "New Zealand",
    PG: "Papua New Guinea",
    FJ: "Fiji",
    SB: "Solomon Islands",
    WS: "Samoa",
    TO: "Tonga",
    VU: "Vanuatu",
    NR: "Nauru",
    TV: "Tuvalu",
  };

  return countryNames[countryCode] || countryCode || null;
}
